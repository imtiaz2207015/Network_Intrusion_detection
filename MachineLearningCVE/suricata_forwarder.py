#!/usr/bin/env python3
"""
Suricata eve.json -> SentinelIQ Alert Forwarder for Raspberry Pi.

Tails /var/log/suricata/eve.json (with inode rotation tracking and offset state),
filters and normalizes Suricata alerts, groups bursts per (src_ip, attack_type)
to at most 1 alert per 60s, enforces a 30 posts/min global cap, and posts to
{PLATFORM_URL}/api/alerts/ingest using the existing X-Service-Key header.
"""

from collections import deque
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
import socket
import time
import urllib.error
import urllib.request

log = logging.getLogger("suricata_forwarder")

DEFAULT_PLATFORM_URL = "http://127.0.0.1:8088"
DEFAULT_EVE_PATH = "/var/log/suricata/eve.json"
DEFAULT_STATE_PATH = "/var/lib/suricata-forwarder/state.json"

GROUP_WINDOW_SEC = 60.0
GROUP_COALESCE_SEC = 2.0
MAX_POSTS_PER_MIN = 30
MAX_QUEUE_SIZE = 500
TEST_RULE_SID = 1000001

CRITICAL_CATEGORIES = (
    "trojan",
    "exploit",
    "admin privilege gain",
    "administrator privilege gain",
    "web application attack",
)


def _env_flag(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def get_local_ips():
    """Returns a set of local IP addresses on this host (never forwarded as attacker src)."""
    ips = set()
    for raw in (os.environ.get("LOCAL_IPS") or "").split(","):
        raw = raw.strip()
        if raw:
            try:
                ips.add(str(ipaddress.ip_address(raw)))
            except ValueError:
                pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0].split("%")[0]
            try:
                ips.add(str(ipaddress.ip_address(addr)))
            except ValueError:
                pass
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except Exception:
        pass
    ips.discard("0.0.0.0")
    return ips


def is_ignored_source_ip(src_ip, local_ips=None):
    """Returns True if src_ip is invalid, loopback, or one of the Pi's own IPs."""
    if not src_ip:
        return True
    try:
        addr = ipaddress.ip_address(str(src_ip).strip())
    except ValueError:
        return True
    if addr.is_loopback or addr.is_unspecified:
        return True
    if local_ips and str(addr) in local_ips:
        return True
    return False


def map_attack_type(signature, category):
    """
    Maps a Suricata alert signature & category to a SentinelIQ attack type:
    - Any signature starting with 'ET SCAN' -> 'PortScan' regardless of category.
    - 'OUTBOUND' in a signature is treated as a label only (never alters direction).
    - Categories:
      * denial of service -> 'DoS'
      * web application attack -> 'Web Attack'
      * trojan -> 'Malware'
      * anything else -> the signature name
    """
    sig = str(signature or "").strip()
    if sig.startswith("ET SCAN"):
        return "PortScan"
    cat = str(category or "").strip().lower()
    if "denial of service" in cat:
        return "DoS"
    if "web application attack" in cat:
        return "Web Attack"
    if "trojan" in cat:
        return "Malware"
    return sig or "Suricata Alert"


def map_severity(suricata_severity, category):
    """
    Maps Suricata numeric severity (1, 2, 3) & category to SentinelIQ severity:
    - 1 -> Critical if category matches trojan / exploit / admin privilege gain / web application attack; else High
    - 2 -> Medium
    - 3 -> Low
    """
    try:
        sev_num = int(suricata_severity)
    except (TypeError, ValueError):
        return "Medium"
    cat = str(category or "").strip().lower()
    if sev_num == 1:
        if any(kw in cat for kw in CRITICAL_CATEGORIES):
            return "Critical"
        return "High"
    if sev_num == 2:
        return "Medium"
    if sev_num == 3:
        return "Low"
    return "Medium"


def normalize_timestamp(ts_raw):
    """Converts Suricata ISO-8601 timestamp to 'YYYY-MM-DD HH:MM:SS'."""
    if not ts_raw:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    s = str(ts_raw).strip()
    try:
        # Handle +0000 / -0500 without colon in Python 3.9+ / 3.11+
        if len(s) >= 5 and s[-5] in ("+", "-") and s[-4:].isdigit():
            s = s[:-2] + ":" + s[-2:]
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return s.replace("T", " ")[:19]


def parse_eve_line(
    line,
    *,
    local_ips=None,
    forward_decoder_events=None,
    forward_test_rule=None,
):
    """
    Parses one JSON line from Suricata eve.json.
    Returns a normalized event dict ready for grouping, or None if the line
    is invalid JSON, not an alert, or filtered out by policy.
    """
    if not line or not line.strip():
        return None
    try:
        ev = json.loads(line)
    except (ValueError, TypeError):
        log.warning("Skipping malformed JSON line in eve.json")
        return None
    if not isinstance(ev, dict):
        return None
    if ev.get("event_type") != "alert":
        return None

    alert = ev.get("alert")
    if not isinstance(alert, dict):
        return None

    signature = str(alert.get("signature") or "").strip()
    if not signature:
        return None

    if forward_decoder_events is None:
        forward_decoder_events = _env_flag("FORWARD_DECODER_EVENTS")
    if forward_test_rule is None:
        forward_test_rule = _env_flag("FORWARD_TEST_RULE")

    # Ignore Suricata decoder/protocol events unless explicitly enabled
    if signature.startswith("SURICATA ") and not forward_decoder_events:
        return None

    raw_sid = alert.get("signature_id")
    signature_id = None
    if raw_sid is not None and not isinstance(raw_sid, bool):
        try:
            signature_id = int(raw_sid)
        except (TypeError, ValueError):
            signature_id = None

    # Ignore local test rule (sid 1000001) unless explicitly enabled
    if signature_id == TEST_RULE_SID and not forward_test_rule:
        return None

    # Never swap src_ip/dest_ip even if signature contains 'OUTBOUND' (label only)
    src_ip = str(ev.get("src_ip") or "").strip()
    if is_ignored_source_ip(src_ip, local_ips=local_ips):
        return None

    dest_ip = str(ev.get("dest_ip") or "-").strip() or "-"
    dest_port = ev.get("dest_port")
    dport = str(dest_port) if dest_port not in (None, "") else "-"
    category = str(alert.get("category") or "").strip()
    attack_type = map_attack_type(signature, category)
    sev = map_severity(alert.get("severity"), category)
    ts = normalize_timestamp(ev.get("timestamp"))

    return {
        "time": ts,
        "type": attack_type,
        "src": src_ip,
        "dst": dest_ip,
        "dport": dport,
        "signature": signature,
        "signature_id": signature_id,
        "category": category,
        "severity": sev,
        "source": "suricata",
    }


def build_group_payload(first_event, count=None, signatures=None):
    """Builds a single /api/alerts/ingest payload from grouped Suricata event(s)."""
    if isinstance(first_event, list):
        events = first_event
        first = events[0]
        total = len(events)
        unique_sigs = []
        for ev in events:
            sig = ev["signature"]
            if len(unique_sigs) < 5 and sig not in unique_sigs:
                unique_sigs.append(sig)
    else:
        first = first_event
        total = int(count) if count is not None else 1
        unique_sigs = list(signatures) if signatures is not None else [first["signature"]]

    top3 = unique_sigs[:3]
    sig_preview = "; ".join(top3)
    if total > 1:
        detail = f"{total} merged signatures: {sig_preview}"
    else:
        detail = f"1 merged signature: {sig_preview}"

    return {
        "time": first["time"],
        "type": first["type"],
        "src": first["src"],
        "dst": first["dst"],
        "dport": first["dport"],
        "detail": detail[:300],
        "source": "suricata",
        "signature": first["signature"][:300],
        "signature_id": first["signature_id"],
        "severity": first["severity"],
    }


class AlertGrouper:
    """
    Groups Suricata alerts by (src_ip, attack_type) and emits at most one
    merged alert per `window_sec` (default 60s) per group.

    A brief `coalesce_sec` (default 2s) collects simultaneous signatures from a
    single scan burst into one merged alert before emitting.
    """

    MAX_STORED_SIGNATURES = 5

    def __init__(self, window_sec=GROUP_WINDOW_SEC, coalesce_sec=GROUP_COALESCE_SEC):
        self.window_sec = float(window_sec)
        self.coalesce_sec = float(coalesce_sec)
        self._pending = {}     # key -> {"first_seen": ts, "first_event": ev, "count": int, "signatures": [...]}
        self._last_sent = {}   # key -> ts

    def add(self, event, now=None):
        now = time.monotonic() if now is None else float(now)
        key = (event["src"], event["type"])
        bucket = self._pending.get(key)
        if bucket is None:
            self._pending[key] = {
                "first_seen": now,
                "first_event": event,
                "count": 1,
                "signatures": [event["signature"]],
            }
        else:
            bucket["count"] += 1
            sig = event["signature"]
            if len(bucket["signatures"]) < self.MAX_STORED_SIGNATURES and sig not in bucket["signatures"]:
                bucket["signatures"].append(sig)

    def flush_ready(self, now=None, force=False):
        """Returns list of ready ingest payloads whose coalesce & 60s window have elapsed."""
        now = time.monotonic() if now is None else float(now)
        ready = []
        done_keys = []
        for key, bucket in self._pending.items():
            last_sent = self._last_sent.get(key)
            if last_sent is not None:
                due_at = last_sent + self.window_sec
            else:
                due_at = bucket["first_seen"] + self.coalesce_sec
            if force or now >= due_at:
                ready.append(
                    build_group_payload(
                        bucket["first_event"],
                        count=bucket["count"],
                        signatures=bucket["signatures"],
                    )
                )
                self._last_sent[key] = now
                done_keys.append(key)
        for key in done_keys:
            del self._pending[key]
        return ready


class RateLimiter:
    """Sliding 60-second global post cap (default 30 posts/minute) with drop logging."""

    def __init__(self, max_per_minute=MAX_POSTS_PER_MIN):
        self.max_per_minute = int(max_per_minute)
        self._timestamps = deque()
        self.dropped_since_log = 0
        self.total_dropped = 0
        self._last_drop_log = 0.0

    def allow(self, now=None):
        now = time.monotonic() if now is None else float(now)
        cutoff = now - 60.0
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.max_per_minute:
            self.dropped_since_log += 1
            self.total_dropped += 1
            if now - self._last_drop_log >= 10.0:
                log.warning(
                    "Rate cap (%d/min) reached: dropped %d alert(s) (total dropped: %d)",
                    self.max_per_minute,
                    self.dropped_since_log,
                    self.total_dropped,
                )
                self.dropped_since_log = 0
                self._last_drop_log = now
            return False
        self._timestamps.append(now)
        return True


class EveTailer:
    """
    Tails a Suricata eve.json file with inode-based rotation detection and
    persistent state file tracking. Starts at EOF on first run.
    """

    def __init__(self, eve_path=DEFAULT_EVE_PATH, state_path=DEFAULT_STATE_PATH):
        self.eve_path = eve_path
        self.state_path = state_path
        self.inode = None
        self.offset = 0
        self._fh = None
        self._partial = ""
        self._state_loaded = False
        self._load_state()

    def _load_state(self):
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                st = json.load(f)
            if isinstance(st, dict) and "inode" in st and "offset" in st:
                self.inode = int(st["inode"])
                self.offset = max(0, int(st["offset"]))
                self._state_loaded = True
        except Exception as e:
            log.warning("Could not read state file %s: %s", self.state_path, e)

    def _save_state(self):
        if not self.state_path or self.inode is None:
            return
        try:
            parent = os.path.dirname(os.path.abspath(self.state_path))
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            tmp = self.state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"inode": self.inode, "offset": self.offset}, f)
            os.replace(tmp, self.state_path)
        except Exception as e:
            log.warning("Could not save state file %s: %s", self.state_path, e)

    def _open_if_needed(self):
        try:
            st = os.stat(self.eve_path)
        except FileNotFoundError:
            return False

        cur_inode = st.st_ino
        cur_size = st.st_size

        if self._fh is None:
            self._fh = open(self.eve_path, "r", encoding="utf-8", errors="replace")
            if self._state_loaded and self.inode == cur_inode and self.offset <= cur_size:
                self._fh.seek(self.offset)
            elif self._state_loaded and self.inode != cur_inode:
                # Rotated while forwarder was stopped: read new file from start
                self.inode = cur_inode
                self.offset = 0
                self._fh.seek(0)
            else:
                # First run ever: start from end so old alerts are not replayed
                self.inode = cur_inode
                self.offset = cur_size
                self._fh.seek(cur_size)
                self._state_loaded = True
            self._save_state()
            return True

        # Detect rotation by inode change or copytruncate (size < offset)
        if cur_inode != self.inode or cur_size < self.offset:
            log.info("Detected log rotation/truncation on %s; reopening from start", self.eve_path)
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = open(self.eve_path, "r", encoding="utf-8", errors="replace")
            self.inode = cur_inode
            self.offset = 0
            self._partial = ""
            self._save_state()

        return True

    def read_lines(self):
        """Reads any newly appended complete lines and updates the persisted offset."""
        if not self._open_if_needed():
            return []
        lines = []
        while True:
            chunk = self._fh.readline()
            if not chunk:
                break
            if not chunk.endswith("\n"):
                self._partial += chunk
                break
            full = self._partial + chunk
            self._partial = ""
            lines.append(full.rstrip("\r\n"))
        new_off = self._fh.tell()
        if new_off != self.offset:
            self.offset = new_off
            self._save_state()
        return lines

    def close(self):
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None


class SuricataForwarder:
    """Coordinates tailing, parsing, grouping, rate-limiting, bounded queueing, and HTTP retry."""

    def __init__(
        self,
        platform_url=None,
        sensor_key=None,
        eve_path=None,
        state_path=None,
        *,
        local_ips=None,
        forward_decoder_events=None,
        forward_test_rule=None,
        group_window_sec=GROUP_WINDOW_SEC,
        group_coalesce_sec=GROUP_COALESCE_SEC,
        max_posts_per_min=MAX_POSTS_PER_MIN,
        max_queue_size=MAX_QUEUE_SIZE,
        poster=None,
    ):
        server_url = (os.environ.get("SERVER_URL") or "").strip().rstrip("/")
        if platform_url or os.environ.get("PLATFORM_URL"):
            base = (platform_url or os.environ.get("PLATFORM_URL") or DEFAULT_PLATFORM_URL).rstrip("/")
            self.ingest_url = f"{base}/api/alerts/ingest"
            self._use_batch_endpoint = False
        elif server_url:
            self.ingest_url = f"{server_url}/api/ingest/alerts"
            self._use_batch_endpoint = True
        else:
            self.ingest_url = f"{DEFAULT_PLATFORM_URL}/api/alerts/ingest"
            self._use_batch_endpoint = False
        self.sensor_key = (sensor_key if sensor_key is not None else os.environ.get("SENSOR_KEY", "")).strip()
        self.eve_path = eve_path or os.environ.get("EVE_PATH") or DEFAULT_EVE_PATH
        self.state_path = state_path or os.environ.get("STATE_PATH") or DEFAULT_STATE_PATH
        self.local_ips = get_local_ips() if local_ips is None else set(local_ips)
        self.forward_decoder_events = forward_decoder_events
        self.forward_test_rule = forward_test_rule
        self.tailer = EveTailer(self.eve_path, self.state_path)
        self.grouper = AlertGrouper(window_sec=group_window_sec, coalesce_sec=group_coalesce_sec)
        self.rate_limiter = RateLimiter(max_per_minute=max_posts_per_min)
        self.queue = deque(maxlen=int(max_queue_size))
        self.queue_dropped = 0
        self._backoff_sec = 1.0
        self._next_retry_at = 0.0
        self._poster = poster or self._http_post

    def _http_post(self, payload):
        if not self.sensor_key:
            raise RuntimeError("SENSOR_KEY is not set")
        body = {"alerts": [payload]} if self._use_batch_endpoint else payload
        req = urllib.request.Request(
            self.ingest_url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Sensor-Key": self.sensor_key,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300

    def enqueue(self, payload):
        if len(self.queue) >= self.queue.maxlen:
            self.queue_dropped += 1
        self.queue.append(payload)

    def drain_queue(self, now=None):
        """Attempts to send queued alerts with exponential backoff on failure."""
        now = time.monotonic() if now is None else float(now)
        if not self.queue or now < self._next_retry_at:
            return 0
        sent = 0
        while self.queue:
            if not self.rate_limiter.allow(now=now):
                # Cap reached: drop the oldest pending alert so queue doesn't stall
                self.queue.popleft()
                continue
            payload = self.queue[0]
            try:
                ok = self._poster(payload)
                if not ok:
                    raise RuntimeError("Non-2xx response from platform")
                self.queue.popleft()
                sent += 1
                self._backoff_sec = 1.0
                self._next_retry_at = 0.0
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    wait = max(30.0, self._backoff_sec)
                    log.error(
                        "sensor key rejected, check SENSOR_KEY (HTTP %d); retrying in %.1fs (queued=%d)",
                        e.code,
                        wait,
                        len(self.queue),
                    )
                    self._next_retry_at = now + wait
                    self._backoff_sec = min(300.0, wait * 2.0)
                    break
                if e.code in (400, 422):
                    log.warning("Dropping invalid alert payload (HTTP %d)", e.code)
                    self.queue.popleft()
                    continue
                log.warning(
                    "Platform HTTP %d error; retrying in %.1fs (queued=%d)",
                    e.code,
                    self._backoff_sec,
                    len(self.queue),
                )
                self._next_retry_at = now + self._backoff_sec
                self._backoff_sec = min(60.0, self._backoff_sec * 2.0)
                break
            except Exception as e:
                log.warning(
                    "Platform unreachable (%s); retrying in %.1fs (queued=%d)",
                    type(e).__name__,
                    self._backoff_sec,
                    len(self.queue),
                )
                self._next_retry_at = now + self._backoff_sec
                self._backoff_sec = min(60.0, self._backoff_sec * 2.0)
                break
        return sent

    def poll_once(self, now=None, force_flush=False):
        now = time.monotonic() if now is None else float(now)
        for line in self.tailer.read_lines():
            ev = parse_eve_line(
                line,
                local_ips=self.local_ips,
                forward_decoder_events=self.forward_decoder_events,
                forward_test_rule=self.forward_test_rule,
            )
            if ev is not None:
                self.grouper.add(ev, now=now)
        for payload in self.grouper.flush_ready(now=now, force=force_flush):
            self.enqueue(payload)
        return self.drain_queue(now=now)

    def run_forever(self, poll_interval=0.5):
        if not self.sensor_key:
            log.error("SENSOR_KEY is not set; exiting.")
            raise SystemExit(1)
        log.info("Starting Suricata forwarder: eve=%s -> %s", self.eve_path, self.ingest_url)
        try:
            while True:
                self.poll_once()
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            log.info("Suricata forwarder stopped by user")
        finally:
            self.tailer.close()


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    fwd = SuricataForwarder()
    fwd.run_forever()


if __name__ == "__main__":
    main()
