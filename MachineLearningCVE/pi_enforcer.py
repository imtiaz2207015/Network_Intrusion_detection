#!/usr/bin/env python3
"""
SentinelIQ Raspberry Pi Host Firewall Enforcer (iptables).

Runs directly on the Raspberry Pi HOST (not in Docker, not on Windows).
Polls GET {PLATFORM_URL}/api/alerts/sensor/blocked-ips with X-Sensor-Key,
and reconciles a dedicated iptables chain (NIDS_BLOCK) jumped from INPUT
at position 1.

DRY_RUN=1 is the default: logs iptables commands without modifying rules.
Set DRY_RUN=0 to apply real firewall changes (requires root / CAP_NET_ADMIN).
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

log = logging.getLogger("pi_enforcer")

DEFAULT_PLATFORM_URL = "http://127.0.0.1:8088"
DEFAULT_POLL_INTERVAL = 10.0
MAX_BACKOFF_SEC = 300.0
CHAIN_NAME = "NIDS_BLOCK"
IPTABLES_BIN = "iptables"

_RULE_SRC_RE = re.compile(r"^-A\s+" + re.escape(CHAIN_NAME) + r"\s+-s\s+([0-9a-fA-F.:/]+)\s+-j\s+DROP\s*$")


def _env_dry_run():
    raw = os.environ.get("DRY_RUN", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _env_poll_interval():
    try:
        return max(1.0, float(os.environ.get("POLL_INTERVAL", str(DEFAULT_POLL_INTERVAL))))
    except ValueError:
        return DEFAULT_POLL_INTERVAL


def validate_ipv4(raw_ip):
    """Validate and normalize an IPv4 address string. Returns canonical str or None."""
    if not isinstance(raw_ip, str):
        return None
    s = raw_ip.strip()
    if not s or "/" in s:
        return None
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if not isinstance(addr, ipaddress.IPv4Address):
        return None
    return str(addr)


def parse_ip_list_env(raw):
    """Parse a comma-separated list of IP addresses, ignoring invalid entries."""
    out = set()
    for item in (raw or "").split(","):
        ip = validate_ipv4(item)
        if ip:
            out.add(ip)
    return out


def get_local_ips():
    """Return local IPv4 addresses on this host (never blocked)."""
    ips = {"127.0.0.1"}
    ips |= parse_ip_list_env(os.environ.get("LOCAL_IPS", ""))
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = validate_ipv4(info[4][0].split("%")[0])
            if ip:
                ips.add(ip)
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = validate_ipv4(s.getsockname()[0])
            if ip:
                ips.add(ip)
    except Exception:
        pass
    ips.discard("0.0.0.0")
    return ips


def build_protected_ips(extra_protected=None, local_ips=None):
    """Build the set of IPs that must never be blocked."""
    protected = {"127.0.0.1"}
    protected |= (get_local_ips() if local_ips is None else set(local_ips))
    protected |= parse_ip_list_env(os.environ.get("PROTECTED_IPS", ""))
    if extra_protected:
        for raw in extra_protected:
            ip = validate_ipv4(str(raw))
            if ip:
                protected.add(ip)
    return protected


def is_protected_ip(ip, protected_ips):
    """Return True if ip is loopback, unspecified, or in protected_ips."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_loopback or addr.is_unspecified:
        return True
    return str(addr) in protected_ips


def parse_blocks_response(data, now_ts=None):
    """Parse GET /api/alerts/sensor/blocked-ips response into (raw_ips, allowlist_ips).

    Supports both:
      - {"ips": ["1.2.3.4", ...], "allowlist": [...]}
      - {"ips": [{"ip": "1.2.3.4", "expires_at": null}, ...]}
      - {"blocked": [{"ip": "1.2.3.4", "expires_at": null}, ...]}
    Null expires_at means blocked until unblocked.
    """
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object from sensor blocks endpoint")
    now = time.time() if now_ts is None else float(now_ts)

    entries = data.get("ips")
    if entries is None:
        entries = data.get("blocked")
    if not isinstance(entries, list):
        raise ValueError("Missing 'ips' list in sensor blocks response")

    raw_ips = []
    for item in entries:
        if isinstance(item, str):
            raw_ips.append(item)
        elif isinstance(item, dict):
            ip_val = item.get("ip")
            exp = item.get("expires_at")
            if exp is not None:
                try:
                    if float(exp) <= now:
                        continue  # already expired
                except (TypeError, ValueError):
                    pass
            if ip_val is not None:
                raw_ips.append(str(ip_val))

    allowlist = []
    raw_allow = data.get("allowlist")
    if isinstance(raw_allow, list):
        allowlist = [str(x) for x in raw_allow if x is not None]

    return raw_ips, allowlist


class IptablesBackend:
    """Thin, safe wrapper around iptables using subprocess.run with argument lists only."""

    def __init__(self, chain=CHAIN_NAME, dry_run=True, runner=None):
        self.chain = chain
        self.dry_run = bool(dry_run)
        self._runner = runner or subprocess.run
        self._dry_state = set()

    def _run(self, args, *, mutating=False):
        cmd = [IPTABLES_BIN] + list(args)
        if mutating and self.dry_run:
            log.info("[DRY_RUN] would run: %s", " ".join(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return self._runner(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )

    def chain_exists(self):
        res = self._run(["-L", self.chain, "-n"], mutating=False)
        return res.returncode == 0

    def ensure_chain_and_jump(self):
        if self.dry_run:
            self._run(["-N", self.chain], mutating=True)
            self._run(["-I", "INPUT", "1", "-j", self.chain], mutating=True)
            return

        if not self.chain_exists():
            res = self._run(["-N", self.chain], mutating=True)
            if res.returncode != 0:
                raise RuntimeError(f"Failed to create chain {self.chain}: {res.stderr.strip()}")
            log.info("Created iptables chain %s", self.chain)

        chk = self._run(["-C", "INPUT", "-j", self.chain], mutating=False)
        if chk.returncode != 0:
            ins = self._run(["-I", "INPUT", "1", "-j", self.chain], mutating=True)
            if ins.returncode != 0:
                raise RuntimeError(f"Failed to insert INPUT jump to {self.chain}: {ins.stderr.strip()}")
            log.info("Inserted INPUT position-1 jump to %s", self.chain)

    def current_blocked_ips(self):
        if self.dry_run:
            return set(self._dry_state)
        res = self._run(["-S", self.chain], mutating=False)
        if res.returncode != 0:
            return set()
        ips = set()
        for line in (res.stdout or "").splitlines():
            m = _RULE_SRC_RE.match(line.strip())
            if not m:
                continue
            raw = m.group(1)
            if raw.endswith("/32"):
                raw = raw[:-3]
            ip = validate_ipv4(raw)
            if ip:
                ips.add(ip)
        return ips

    def add_ip(self, ip):
        valid = validate_ipv4(ip)
        if not valid:
            raise ValueError(f"Refusing to pass invalid IP to iptables: {ip!r}")
        res = self._run(["-A", self.chain, "-s", valid, "-j", "DROP"], mutating=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to add DROP rule for {valid}: {res.stderr.strip()}")
        if self.dry_run:
            self._dry_state.add(valid)
        else:
            log.info("Blocked IP %s in chain %s", valid, self.chain)

    def remove_ip(self, ip):
        valid = validate_ipv4(ip)
        if not valid:
            raise ValueError(f"Refusing to pass invalid IP to iptables: {ip!r}")
        res = self._run(["-D", self.chain, "-s", valid, "-j", "DROP"], mutating=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to remove DROP rule for {valid}: {res.stderr.strip()}")
        if self.dry_run:
            self._dry_state.discard(valid)
        else:
            log.info("Removed block for IP %s from chain %s", valid, self.chain)

    def status_text(self):
        lines = []
        chk = self._run(["-C", "INPUT", "-j", self.chain], mutating=False)
        lines.append(f"INPUT -> {self.chain} jump: {'PRESENT' if chk.returncode == 0 else 'MISSING'}")
        res = self._run(["-L", self.chain, "-n", "-v", "--line-numbers"], mutating=False)
        if res.returncode == 0:
            lines.append((res.stdout or "").rstrip())
        else:
            lines.append(f"Chain {self.chain} does not exist (or insufficient privileges).")
        return "\n".join(lines)

    def cleanup(self):
        if self.dry_run:
            self._run(["-D", "INPUT", "-j", self.chain], mutating=True)
            self._run(["-F", self.chain], mutating=True)
            self._run(["-X", self.chain], mutating=True)
            self._dry_state.clear()
            return

        # Remove all INPUT jumps to NIDS_BLOCK (defensive against duplicates)
        while self._run(["-C", "INPUT", "-j", self.chain], mutating=False).returncode == 0:
            res = self._run(["-D", "INPUT", "-j", self.chain], mutating=True)
            if res.returncode != 0:
                log.warning("Could not remove INPUT jump to %s: %s", self.chain, res.stderr.strip())
                break
            log.info("Removed INPUT jump to %s", self.chain)

        if self.chain_exists():
            fl = self._run(["-F", self.chain], mutating=True)
            if fl.returncode != 0:
                log.warning("Could not flush %s: %s", self.chain, fl.stderr.strip())
            dl = self._run(["-X", self.chain], mutating=True)
            if dl.returncode != 0:
                log.warning("Could not delete %s: %s", self.chain, dl.stderr.strip())
            else:
                log.info("Flushed and deleted chain %s", self.chain)
        else:
            log.info("Chain %s does not exist; nothing to clean up", self.chain)


class PiEnforcer:
    """Polls SentinelIQ for active blocks and reconciles NIDS_BLOCK iptables rules."""

    def __init__(
        self,
        platform_url=None,
        sensor_key=None,
        *,
        poll_interval=None,
        dry_run=None,
        protected_ips=None,
        local_ips=None,
        backend=None,
        fetcher=None,
    ):
        base = (
            platform_url
            or os.environ.get("PLATFORM_URL")
            or os.environ.get("SERVER_URL")
            or DEFAULT_PLATFORM_URL
        ).strip().rstrip("/")
        self.blocks_url = os.environ.get("BLOCKS_URL", "").strip() or f"{base}/api/alerts/sensor/blocked-ips"
        self.sensor_key = (
            sensor_key if sensor_key is not None else os.environ.get("SENSOR_KEY", "")
        ).strip()
        self.poll_interval = _env_poll_interval() if poll_interval is None else max(1.0, float(poll_interval))
        self.dry_run = _env_dry_run() if dry_run is None else bool(dry_run)
        self.protected_ips = build_protected_ips(extra_protected=protected_ips, local_ips=local_ips)
        self.backend = backend or IptablesBackend(chain=CHAIN_NAME, dry_run=self.dry_run)
        self._fetcher = fetcher or self._http_fetch
        self._backoff_sec = self.poll_interval

    def _http_fetch(self):
        if not self.sensor_key:
            raise RuntimeError("SENSOR_KEY is not set")
        req = urllib.request.Request(
            self.blocks_url,
            headers={
                "Accept": "application/json",
                "X-Sensor-Key": self.sensor_key,
            },
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw)

    def filter_desired_ips(self, raw_ips, api_allowlist=None):
        effective_protected = set(self.protected_ips)
        if api_allowlist:
            for item in api_allowlist:
                valid = validate_ipv4(str(item))
                if valid:
                    effective_protected.add(valid)

        desired = set()
        for raw in raw_ips:
            ip = validate_ipv4(raw)
            if not ip:
                log.warning("Rejected invalid IP from platform: %r", raw)
                continue
            if is_protected_ip(ip, effective_protected):
                log.warning("Skipping protected IP %s (will not block)", ip)
                continue
            desired.add(ip)
        return desired

    def sync_once(self, now_ts=None):
        """Perform one poll and reconcile NIDS_BLOCK.

        Returns dict {"ok": bool, "added": [...], "removed": [...], "active": [...]}.
        On API failure, leaves existing rules untouched.
        """
        try:
            data = self._fetcher()
            raw_ips, api_allowlist = parse_blocks_response(data, now_ts=now_ts)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                log.error("Sensor key rejected (HTTP %d); check SENSOR_KEY. Keeping existing rules.", e.code)
            else:
                log.warning("Platform returned HTTP %d; keeping existing rules unchanged.", e.code)
            self._backoff_sec = min(MAX_BACKOFF_SEC, max(self.poll_interval, self._backoff_sec * 2.0))
            return {"ok": False, "added": [], "removed": [], "active": []}
        except Exception as e:
            log.warning("Platform unreachable (%s: %s); keeping existing rules unchanged.", type(e).__name__, e)
            self._backoff_sec = min(MAX_BACKOFF_SEC, max(self.poll_interval, self._backoff_sec * 2.0))
            return {"ok": False, "added": [], "removed": [], "active": []}

        self._backoff_sec = self.poll_interval
        desired = self.filter_desired_ips(raw_ips, api_allowlist=api_allowlist)

        self.backend.ensure_chain_and_jump()
        current = self.backend.current_blocked_ips()

        to_add = sorted(desired - current)
        to_remove = sorted(current - desired)

        for ip in to_add:
            self.backend.add_ip(ip)
        for ip in to_remove:
            self.backend.remove_ip(ip)

        if to_add or to_remove:
            log.info(
                "Reconciled %s: +%d added, -%d removed, %d active%s",
                CHAIN_NAME,
                len(to_add),
                len(to_remove),
                len(desired),
                " [DRY_RUN]" if self.dry_run else "",
            )
        return {"ok": True, "added": to_add, "removed": to_remove, "active": sorted(desired)}

    def run_forever(self):
        if not self.sensor_key:
            log.error("SENSOR_KEY is not set; exiting.")
            raise SystemExit(1)
        log.info(
            "Starting Pi firewall enforcer: url=%s poll=%.1fs dry_run=%s protected=%d",
            self.blocks_url,
            self.poll_interval,
            self.dry_run,
            len(self.protected_ips),
        )
        try:
            while True:
                res = self.sync_once()
                wait = self.poll_interval if res["ok"] else self._backoff_sec
                if not res["ok"]:
                    log.info("Retrying in %.1fs", wait)
                time.sleep(wait)
        except KeyboardInterrupt:
            log.info("Pi firewall enforcer stopped by user")


def build_arg_parser():
    p = argparse.ArgumentParser(description="SentinelIQ Raspberry Pi iptables firewall enforcer")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--status", action="store_true", help="Print NIDS_BLOCK chain contents and exit")
    group.add_argument("--cleanup", action="store_true", help="Flush/delete NIDS_BLOCK and remove INPUT jump")
    group.add_argument("--once", action="store_true", help="Run one poll/reconcile cycle and exit")
    return p


def main(argv=None):
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = build_arg_parser().parse_args(argv)
    dry_run = _env_dry_run()

    if args.status:
        backend = IptablesBackend(chain=CHAIN_NAME, dry_run=False)
        print(backend.status_text())
        return 0

    if args.cleanup:
        backend = IptablesBackend(chain=CHAIN_NAME, dry_run=dry_run)
        backend.cleanup()
        return 0

    enforcer = PiEnforcer(dry_run=dry_run)
    if args.once:
        res = enforcer.sync_once()
        return 0 if res["ok"] else 1

    enforcer.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
