import warnings
warnings.filterwarnings('ignore')
import os
os.environ["PYTHONWARNINGS"] = "ignore"
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, get_if_addr
from collections import defaultdict
import time
import numpy as np
import joblib
import csv
import json
import threading
import socket
import urllib.error
import urllib.request
from datetime import datetime

# ---------------- Alert output ----------------
ALERT_FILE = "alerts.csv"
SERVER_URL = os.environ.get("SERVER_URL", "").strip().rstrip("/")
ALERT_API = (
    f"{SERVER_URL}/api/ingest/alerts"
    if SERVER_URL
    else os.environ.get("ALERT_API", "http://127.0.0.1:8088/api/ingest/alerts")
)
SENSOR_KEY = os.environ.get("SENSOR_KEY", "").strip()
HEARTBEAT_INTERVAL = max(5, int(os.environ.get("HEARTBEAT_INTERVAL", "30") or 30))
ALERT_QUEUE_FILE = os.environ.get("ALERT_QUEUE_FILE", "alert_queue.jsonl")
QUEUE_BATCH_SIZE = 50
QUEUE_MAX_ITEMS = 10000
_queue_lock = threading.Lock()
_queue_wakeup = threading.Event()
last_alert = {}
seen_flows = set()

# ---------------- Trusted / noise filtering ----------------
def local_ips():
    ips = set()
    for i in get_if_list():
        try:
            ips.add(get_if_addr(i))
        except Exception:
            pass
    ips.discard("0.0.0.0")
    return ips


# optional extra trusted IPs: $env:TRUSTED_IPS = "192.168.0.1,192.168.0.50"
TRUSTED_IPS = {x.strip() for x in os.environ.get("TRUSTED_IPS", "").split(",") if x.strip()}
IGNORE_SRC = local_ips() | TRUSTED_IPS
START_TIME = time.time()
packet_count = 0
HEARTBEAT_API = (
    f"{SERVER_URL}/api/ingest/heartbeat"
    if SERVER_URL
    else ALERT_API.replace("/api/ingest/alerts", "/api/ingest/heartbeat").replace("/ingest", "/heartbeat")
)


def _sensor_headers():
    return {
        "Content-Type": "application/json",
        "X-Sensor-Key": SENSOR_KEY,
    }


def _read_queue_file(path=None):
    qpath = path or ALERT_QUEUE_FILE
    if not os.path.exists(qpath):
        return []
    items = []
    with open(qpath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    items.append(obj)
            except json.JSONDecodeError:
                continue
    return items


def _write_queue_file(items, path=None):
    qpath = path or ALERT_QUEUE_FILE
    parent = os.path.dirname(os.path.abspath(qpath))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = qpath + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for obj in items[-QUEUE_MAX_ITEMS:]:
            f.write(json.dumps(obj, separators=(",", ":")) + "\n")
    os.replace(tmp, qpath)


def _append_queue_file(payload, path=None):
    qpath = path or ALERT_QUEUE_FILE
    parent = os.path.dirname(os.path.abspath(qpath))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(qpath, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, separators=(",", ":")) + "\n")


def _send_alert_batch(batch):
    body = {"alerts": batch} if ALERT_API.rstrip("/").endswith("/ingest/alerts") else batch[0]
    req = urllib.request.Request(
        ALERT_API,
        data=json.dumps(body).encode("utf-8"),
        headers=_sensor_headers(),
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=5)
    try:
        if hasattr(resp, "read"):
            resp.read()
    finally:
        if hasattr(resp, "close"):
            resp.close()


def flush_alert_queue(path=None):
    """Flush queued alerts in FIFO order. Returns (sent_count, remaining_count, retry_backoff_hint)."""
    if not SENSOR_KEY:
        return 0, 0, None
    sent_total = 0
    while True:
        with _queue_lock:
            items = _read_queue_file(path)
            if not items:
                return sent_total, 0, None
            batch = items[:QUEUE_BATCH_SIZE]
            rest = items[QUEUE_BATCH_SIZE:]
        try:
            _send_alert_batch(batch)
        except urllib.error.HTTPError as e:
            if e.code in (400, 422):
                print(f"[WARN] Dropping invalid queued alert batch (HTTP {e.code})")
                with _queue_lock:
                    cur = _read_queue_file(path)
                    _write_queue_file(cur[len(batch):], path)
                continue
            if e.code in (401, 403):
                print(f"[ERROR] Sensor key rejected by server (HTTP {e.code}); check SENSOR_KEY")
                return sent_total, len(items), 30.0
            print(f"[WARN] Server error flushing alert queue (HTTP {e.code}); will retry")
            return sent_total, len(items), None
        except Exception as e:
            print(f"[WARN] Could not flush alert queue ({e}); will retry")
            return sent_total, len(items), None

        with _queue_lock:
            cur = _read_queue_file(path)
            remaining = cur[len(batch):]
            _write_queue_file(remaining, path)
            sent_total += len(batch)
            if not remaining:
                return sent_total, 0, None


def queue_flush_loop():
    backoff = 1.0
    while True:
        sent, remaining, hint = flush_alert_queue()
        if remaining == 0:
            backoff = 1.0
            _queue_wakeup.wait(timeout=5.0)
            _queue_wakeup.clear()
        else:
            if hint is not None:
                backoff = min(300.0, max(hint, backoff * 2.0))
            else:
                backoff = min(60.0, max(1.0, backoff * 2.0))
            _queue_wakeup.wait(timeout=backoff)
            _queue_wakeup.clear()


def heartbeat_loop():
    while True:
        try:
            payload = {
                "host": socket.gethostname(),
                "packets": packet_count,
                "uptime": int(time.time() - START_TIME),
            }
            req = urllib.request.Request(
                HEARTBEAT_API,
                data=json.dumps(payload).encode("utf-8"),
                headers=_sensor_headers(),
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5).close()
        except Exception:
            pass          # platform down: try again on next interval
        time.sleep(HEARTBEAT_INTERVAL)
UDP_NOISE_PORTS = {53, 123, 137, 138, 1900, 5353, 5355}   # DNS, NTP, NetBIOS, SSDP, mDNS, LLMNR
ML_MIN_CONF = float(os.environ.get("ML_MIN_CONF", "0.80"))   # ignore ML alerts below 80% confidence
outbound_udp = {}        # (remote_ip, remote_port, local_port) -> last time we sent to it
RESPONSE_WINDOW = 30     # seconds a UDP reply still counts as "expected"


def is_noise_dst(ip):
    """Multicast (224-239.x.x.x) or broadcast (x.x.x.255) destinations are normal LAN chatter."""
    try:
        first = int(ip.split(".")[0])
    except ValueError:
        return False
    return 224 <= first <= 239 or ip.endswith(".255")


def post_alert(payload):
    """Send one alert to the server; queue locally on failure to preserve FIFO order."""
    if not SENSOR_KEY:
        return
    with _queue_lock:
        queued = _read_queue_file()
        if queued:
            _append_queue_file(payload)
            _queue_wakeup.set()
            return
    try:
        _send_alert_batch([payload])
    except urllib.error.HTTPError as e:
        if e.code in (400, 422):
            print(f"[WARN] Dropping invalid alert payload (HTTP {e.code})")
            return
        with _queue_lock:
            _append_queue_file(payload)
        _queue_wakeup.set()
        if e.code in (401, 403):
            print(f"[ERROR] Sensor key rejected (HTTP {e.code}); queued alert locally")
        else:
            print(f"[WARN] Server returned HTTP {e.code}; queued alert locally")
    except Exception as e:
        with _queue_lock:
            _append_queue_file(payload)
        _queue_wakeup.set()
        print(f"[WARN] Could not send alert to server ({e}); queued locally")


def log_alert(attack_type, src, dst, dport, detail="", *, source=None, features=None, predicted_class=None, rule=None):
    key = (attack_type, src, dport)
    now = time.time()
    if now - last_alert.get(key, 0) < 10:   # same alert at most once per 10s
        return
    last_alert[key] = now
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1) local CSV (old dashboard + backup)
    new_file = not os.path.exists(ALERT_FILE)
    with open(ALERT_FILE, "a", newline="") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["time", "type", "src", "dst", "dport", "detail"])
        w.writerow([ts, attack_type, src, dst, dport, detail])

    # 2) platform Alert service (non-blocking; optional SHAP/rule metadata)
    payload = {
        "time": ts,
        "type": attack_type,
        "src": src,
        "dst": dst,
        "dport": str(dport),
        "detail": detail,
    }
    if source:
        payload["source"] = source
    if isinstance(features, dict):
        payload["features"] = features
    if predicted_class is not None:
        payload["predicted_class"] = predicted_class
    if isinstance(rule, dict):
        payload["rule"] = rule

    threading.Thread(
        target=post_alert,
        args=(payload,),
        daemon=True).start()

    print(f"[ATTACK - {attack_type}] {src} -> {dst}:{dport} {detail}")


# ---------------- Load model ----------------
print("Loading model...")
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "selected_features_model.pkl")
saved = joblib.load(MODEL_PATH)
model = saved['model']
features = saved['features']
print("Model loaded. Features expected:", len(features))
print("Platform alerts:", "ON -> " + ALERT_API if SENSOR_KEY else "OFF (SENSOR_KEY not set)")
print("Ignoring sources:", ", ".join(sorted(IGNORE_SRC)) or "none")

# Store ongoing flows
flows = defaultdict(lambda: {
    'fwd_packets': [], 'bwd_packets': [],
    'start_time': None, 'last_time': None,
    'init_win_fwd': None, 'init_win_bwd': None
})

# ---------------- PortScan detection ----------------
# key = source_ip, value = list of (dest_port, timestamp)
port_scan_tracker = defaultdict(list)
SCAN_WINDOW = 5           # seconds
SCAN_PORT_THRESHOLD = 10  # distinct ports within window to flag as scan
already_flagged = set()


def check_port_scan(src_ip, dst_port):
    now = time.time()
    port_scan_tracker[src_ip].append((dst_port, now))
    port_scan_tracker[src_ip] = [
        (p, t) for (p, t) in port_scan_tracker[src_ip] if now - t <= SCAN_WINDOW
    ]
    distinct_ports = set(p for p, t in port_scan_tracker[src_ip])
    if len(distinct_ports) >= SCAN_PORT_THRESHOLD:
        if src_ip not in already_flagged:
            obs = f"{len(distinct_ports)} ports in {SCAN_WINDOW}s"
            log_alert(
                "PortScan", src_ip, "-", "-", obs,
                source="rule",
                rule={
                    "name": "PortScan",
                    "condition": f">= {SCAN_PORT_THRESHOLD} distinct destination ports within {SCAN_WINDOW}s",
                    "observed": obs,
                },
            )
            already_flagged.add(src_ip)
        return True
    else:
        already_flagged.discard(src_ip)
        return False


# ---------------- DoS / SYN Flood detection ----------------
dos_syn_tracker = defaultdict(list)
DOS_WINDOW = 5               # seconds
DOS_SYN_THRESHOLD = 100      # >=100 SYNs from one source in 5s = SYN flood
dos_already_flagged = set()

# ---------------- BruteForce detection ----------------
brute_force_tracker = defaultdict(list)
BRUTE_WINDOW = 10            # seconds
BRUTE_SYN_THRESHOLD = 8      # >=8 SYNs to a service port in 10s = brute force
BRUTE_FORCE_PORTS = {21, 22, 23, 3389, 9999}
brute_already_flagged = set()


def _is_port_scan_flagged(src_ip, now):
    """True while src_ip is actively flagged as a PortScan within SCAN_WINDOW."""
    if src_ip not in already_flagged:
        return False
    if src_ip in port_scan_tracker:
        port_scan_tracker[src_ip] = [
            (p, t) for (p, t) in port_scan_tracker[src_ip] if now - t <= SCAN_WINDOW
        ]
        if len({p for p, _ in port_scan_tracker[src_ip]}) >= SCAN_PORT_THRESHOLD:
            return True
    already_flagged.discard(src_ip)
    return False


def check_dos_syn_flood(src_ip, dst_ip):
    """>=100 SYNs from a single source IP within 5s, any destination port."""
    now = time.time()
    if _is_port_scan_flagged(src_ip, now):
        dos_already_flagged.discard(src_ip)
        return False
    dos_syn_tracker[src_ip].append(now)
    dos_syn_tracker[src_ip] = [t for t in dos_syn_tracker[src_ip] if now - t <= DOS_WINDOW]
    count = len(dos_syn_tracker[src_ip])
    if count >= DOS_SYN_THRESHOLD:
        if src_ip not in dos_already_flagged:
            obs = f"{count} SYNs in {DOS_WINDOW}s"
            log_alert(
                "DoS/SYN Flood", src_ip, dst_ip, "any", obs,
                source="rule",
                rule={
                    "name": "DoS/SYN Flood",
                    "condition": f">= {DOS_SYN_THRESHOLD} pure TCP SYN packets from one source within {DOS_WINDOW}s",
                    "observed": obs,
                },
            )
            dos_already_flagged.add(src_ip)
        return True
    else:
        dos_already_flagged.discard(src_ip)
        return False


def check_brute_force(src_ip, dst_ip, dst_port):
    """>=8 SYNs to a specific service port within 10s."""
    if dst_port not in BRUTE_FORCE_PORTS:
        return False
    now = time.time()
    key = (src_ip, dst_ip, dst_port)
    brute_force_tracker[key].append(now)
    brute_force_tracker[key] = [t for t in brute_force_tracker[key] if now - t <= BRUTE_WINDOW]
    attempts = len(brute_force_tracker[key])
    if attempts >= BRUTE_SYN_THRESHOLD:
        if key not in brute_already_flagged:
            obs = f"{attempts} SYNs in {BRUTE_WINDOW}s"
            log_alert(
                "BruteForce", src_ip, dst_ip, dst_port, obs,
                source="rule",
                rule={
                    "name": "BruteForce",
                    "condition": f">= {BRUTE_SYN_THRESHOLD} pure TCP SYN packets to login service port {dst_port} within {BRUTE_WINDOW}s",
                    "observed": obs,
                },
            )
            brute_already_flagged.add(key)
        return True
    else:
        brute_already_flagged.discard(key)
        return False


# ---------------- ICMP Flood detection ----------------
icmp_tracker = defaultdict(list)
ICMP_THRESHOLD = 100
ICMP_WINDOW = 5
icmp_already_flagged = set()

# ---------------- UDP Flood detection ----------------
udp_tracker = defaultdict(list)
UDP_THRESHOLD = 100
UDP_WINDOW = 5
udp_already_flagged = set()


def check_icmp_flood(src_ip, dst_ip):
    """>=100 ICMP packets from one source in 5s."""
    now = time.time()
    icmp_tracker[src_ip].append(now)
    icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if now - t <= ICMP_WINDOW]
    count = len(icmp_tracker[src_ip])
    if count >= ICMP_THRESHOLD:
        if src_ip not in icmp_already_flagged:
            obs = f"{count} ICMP packets in {ICMP_WINDOW}s"
            log_alert(
                "ICMP Flood", src_ip, dst_ip, "-", obs,
                source="rule",
                rule={
                    "name": "ICMP Flood",
                    "condition": f">= {ICMP_THRESHOLD} ICMP packets from one source within {ICMP_WINDOW}s",
                    "observed": obs,
                },
            )
            icmp_already_flagged.add(src_ip)
        return True
    else:
        icmp_already_flagged.discard(src_ip)
        return False


def check_udp_flood(src_ip, dst_ip, dst_port):
    """>=100 UDP packets from one source in 5s."""
    now = time.time()
    udp_tracker[src_ip].append(now)
    udp_tracker[src_ip] = [t for t in udp_tracker[src_ip] if now - t <= UDP_WINDOW]
    count = len(udp_tracker[src_ip])
    if count >= UDP_THRESHOLD:
        if src_ip not in udp_already_flagged:
            obs = f"{count} UDP packets in {UDP_WINDOW}s"
            log_alert(
                "UDP Flood", src_ip, dst_ip, dst_port, obs,
                source="rule",
                rule={
                    "name": "UDP Flood",
                    "condition": f">= {UDP_THRESHOLD} unsolicited UDP packets from one source within {UDP_WINDOW}s",
                    "observed": obs,
                },
            )
            udp_already_flagged.add(src_ip)
        return True
    else:
        udp_already_flagged.discard(src_ip)
        return False


# ---------------- Memory cleanup ----------------

FLOW_TIMEOUT = 60       # drop flows idle for 60s
CLEANUP_EVERY = 30      # run cleanup every 30s
last_cleanup = time.time()


def cleanup(now):
    global last_cleanup
    if now - last_cleanup < CLEANUP_EVERY:
        return
    last_cleanup = now
    for k in [k for k, t in outbound_udp.items() if now - t > RESPONSE_WINDOW]:
        del outbound_udp[k]

    old = [k for k, f in flows.items() if f['last_time'] and now - f['last_time'] > FLOW_TIMEOUT]
    for k in old:
        del flows[k]
    seen_flows.intersection_update(flows.keys())

    for tracker, window in ((dos_syn_tracker, DOS_WINDOW), (brute_force_tracker, BRUTE_WINDOW),
                            (icmp_tracker, ICMP_WINDOW), (udp_tracker, UDP_WINDOW)):
        for k in list(tracker):
            tracker[k] = [t for t in tracker[k] if now - t <= window]
            if not tracker[k]:
                del tracker[k]
    for k in list(port_scan_tracker):
        port_scan_tracker[k] = [(p, t) for (p, t) in port_scan_tracker[k] if now - t <= SCAN_WINDOW]
        if not port_scan_tracker[k]:
            del port_scan_tracker[k]
            already_flagged.discard(k)


# ---------------- Flow features ----------------
def get_flow_key(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if TCP in pkt:
        proto = 'TCP'
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        proto = 'UDP'
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return None
    a = (ip.src, sport)
    b = (ip.dst, dport)
    if a < b:
        return (a[0], b[0], a[1], b[1], proto), 'fwd'
    else:
        return (b[0], a[0], b[1], a[1], proto), 'bwd'


def extract_features(flow):
    fwd = flow['fwd_packets']
    bwd = flow['bwd_packets']
    all_pkts = fwd + bwd

    duration = (flow['last_time'] - flow['start_time']) * 1_000_000
    duration = max(duration, 1)

    total_fwd_bytes = sum(fwd) if fwd else 0
    total_bwd_bytes = sum(bwd) if bwd else 0

    all_lengths = all_pkts if all_pkts else [0]

    flow_bytes_per_s = (total_fwd_bytes + total_bwd_bytes) / (duration / 1_000_000)
    flow_packets_per_s = len(all_pkts) / (duration / 1_000_000)

    down_up_ratio = (len(bwd) / len(fwd)) if len(fwd) > 0 else 0

    feat = {
        'Destination Port': flow.get('dport', 0),
        'Flow Duration': duration,
        'Total Fwd Packets': len(fwd),
        'Total Backward Packets': len(bwd),
        'Total Length of Fwd Packets': total_fwd_bytes,
        'Total Length of Bwd Packets': total_bwd_bytes,
        'Fwd Packet Length Max': max(fwd) if fwd else 0,
        'Fwd Packet Length Min': min(fwd) if fwd else 0,
        'Fwd Packet Length Mean': np.mean(fwd) if fwd else 0,
        'Bwd Packet Length Max': max(bwd) if bwd else 0,
        'Bwd Packet Length Min': min(bwd) if bwd else 0,
        'Bwd Packet Length Mean': np.mean(bwd) if bwd else 0,
        'Flow Bytes/s': flow_bytes_per_s,
        'Flow Packets/s': flow_packets_per_s,
        'Min Packet Length': min(all_lengths),
        'Max Packet Length': max(all_lengths),
        'Packet Length Mean': np.mean(all_lengths),
        'Packet Length Std': np.std(all_lengths),
        'Packet Length Variance': np.var(all_lengths),
        'Average Packet Size': np.mean(all_lengths),
        'Init_Win_bytes_forward': flow.get('init_win_fwd') or 0,
        'Init_Win_bytes_backward': flow.get('init_win_bwd') or 0,
        'Down/Up Ratio': down_up_ratio,
    }
    return feat


# ---------------- Packet handler ----------------
def process_packet(pkt):
    global packet_count
    packet_count += 1
    cleanup(time.time())

    # ICMP has no TCP/UDP flow key, so check it BEFORE the flow-key early return
    if IP in pkt and ICMP in pkt and pkt[IP].src not in IGNORE_SRC:
        check_icmp_flood(pkt[IP].src, pkt[IP].dst)

    result = get_flow_key(pkt)
    if result is None:
        return
    key, direction = result
    flow = flows[key]

    now = time.time()
    if flow['start_time'] is None:
        flow['start_time'] = now
    flow['last_time'] = now

    pkt_len = len(pkt)
    if direction == 'fwd':
        flow['fwd_packets'].append(pkt_len)
    else:
        flow['bwd_packets'].append(pkt_len)

    flow['dport'] = key[3]

    if TCP in pkt:
        win = pkt[TCP].window
        if direction == 'fwd' and flow['init_win_fwd'] is None:
            flow['init_win_fwd'] = win
        elif direction == 'bwd' and flow['init_win_bwd'] is None:
            flow['init_win_bwd'] = win

    # --- Rule-based checks (independent of the ML model) ---
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
    trusted = src_ip in IGNORE_SRC

    response = False
    if UDP in pkt:
        sport = pkt[UDP].sport
        if trusted:
            outbound_udp[(dst_ip, dport, sport)] = now      # remember what we sent
        else:
            response = (src_ip, sport, dport) in outbound_udp   # reply to something we sent

    if TCP in pkt and not trusted:
        flags_int = int(pkt[TCP].flags)
        syn = bool(flags_int & 0x02) and not bool(flags_int & 0x10)  # pure SYN only
        if syn:
            check_port_scan(src_ip, dport)
            check_dos_syn_flood(src_ip, dst_ip)
            check_brute_force(src_ip, dst_ip, dport)

    if UDP in pkt and not trusted and not response and dport not in UDP_NOISE_PORTS and not is_noise_dst(dst_ip):
        check_port_scan(src_ip, dport)
        check_udp_flood(src_ip, dst_ip, dport)

    # --- ML-based prediction on flow (packets 2-5, then every 10th) ---
    total_pkts = len(flow['fwd_packets']) + len(flow['bwd_packets'])
    if total_pkts >= 2 and (total_pkts <= 5 or total_pkts % 10 == 0):
        feat = extract_features(flow)
        X = np.array([[feat[f] for f in features]])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            pred = model.predict(X)[0]
            try:
                conf = float(model.predict_proba(X)[0][list(model.classes_).index(pred)])
            except Exception:
                conf = 1.0
        label = "ATTACK" if pred == 1 else "BENIGN"
        src, dst = key[0], key[1]
        noise = (key[2] in UDP_NOISE_PORTS or key[3] in UDP_NOISE_PORTS
                 or key[2] in (67, 68) or key[3] in (67, 68)
                 or "0.0.0.0" in (key[0], key[1])
                 or is_noise_dst(key[0]) or is_noise_dst(key[1]))
        if label == "ATTACK":
            if not noise and conf >= ML_MIN_CONF:
                clean_feat = {f: float(feat[f]) for f in features}
                pred_val = int(pred) if isinstance(pred, (int, np.integer)) else str(pred)
                log_alert(
                    "ML-Detected", src, dst, key[3],
                    f"pkts={total_pkts}, confidence={conf:.0%}",
                    source="ml",
                    features=clean_feat,
                    predicted_class=pred_val,
                )
        elif key not in seen_flows:
            seen_flows.add(key)
            print(f"[BENIGN] {src} <-> {dst}:{key[3]} ({key[4]})")


if __name__ == "__main__":
    if SENSOR_KEY:
        threading.Thread(target=heartbeat_loop, daemon=True).start()
        threading.Thread(target=queue_flush_loop, daemon=True).start()
    print("Starting live capture... (Ctrl+C to stop)")
    sniff(prn=process_packet, store=False)