import csv
import importlib.util
import json
import os
import pathlib
import sys
from types import SimpleNamespace

import joblib
import pytest
from scapy.all import ARP, ICMP, IP, TCP, UDP

ROOT = pathlib.Path(__file__).resolve().parent.parent
FEATURES = ["Destination Port", "Flow Duration", "Total Fwd Packets"]
STATE = ["flows", "seen_flows", "last_alert", "outbound_udp", "port_scan_tracker",
         "already_flagged", "dos_syn_tracker", "dos_already_flagged",
         "brute_force_tracker", "brute_already_flagged", "icmp_tracker",
         "icmp_already_flagged", "udp_tracker", "udp_already_flagged"]


# ---------- test doubles ----------
class FakeModel:
    """Stands in for the .pkl model: tests choose what it predicts."""
    classes_ = [0, 1]

    def __init__(self):
        self.pred, self.conf = 0, 0.95

    def predict(self, X):
        return [self.pred]

    def predict_proba(self, X):
        p = self.conf
        return [[1 - p, p]] if self.pred == 1 else [[p, 1 - p]]


class Clock:
    """Fake time: only moves when a test says so."""
    def __init__(self):
        self.now = 1_000_000.0

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += s

    def advance(self, s):
        self.now += s


class SyncThread:
    """Runs the 'background' alert upload immediately, so tests stay deterministic."""
    def __init__(self, target, args=(), daemon=None):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)


# ---------- loading the sensor ----------
def find_sensor():
    if os.environ.get("SENSOR_FILE"):
        return pathlib.Path(os.environ["SENSOR_FILE"])
    for folder in (ROOT, ROOT / "sensor", ROOT.parent, ROOT.parent / "sensor"):
        f = folder / "live_feature_extractor.py"
        if f.exists():
            return f
    pytest.fail("live_feature_extractor.py not found - set $env:SENSOR_FILE to its full path",
                pytrace=False)


@pytest.fixture(scope="session")
def sensor_mod():
    path = find_sensor()
    fake = {"model": FakeModel(), "features": FEATURES}
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(joblib, "load", lambda *a, **k: fake)     # skip the real .pkl model
        spec = importlib.util.spec_from_file_location("sensor_app", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["sensor_app"] = mod
        spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def sensor(sensor_mod, monkeypatch):
    for name in STATE:                                       # clean slate for every test
        getattr(sensor_mod, name).clear()
    sensor_mod.model.pred, sensor_mod.model.conf = 0, 0.95
    monkeypatch.setattr(sensor_mod, "IGNORE_SRC", set())     # nobody trusted unless a test says so
    monkeypatch.setattr(sensor_mod, "ML_MIN_CONF", 0.80)
    monkeypatch.setattr(sensor_mod, "last_cleanup", 1e18)    # no surprise cleanups
    monkeypatch.setattr(sensor_mod, "packet_count", 0)
    return sensor_mod


@pytest.fixture()
def clock(sensor, monkeypatch):
    c = Clock()
    monkeypatch.setattr(sensor, "time", c)
    return c


@pytest.fixture()
def alerts_log(sensor, monkeypatch):
    """Replaces log_alert with a recorder: each entry is (type, src, dst, dport, detail)."""
    log = []
    monkeypatch.setattr(sensor, "log_alert", lambda *a, **k: log.append(a))
    return log


# ---------- packet helpers ----------
def tcp(src, dst, dport, flags="S", sport=40000):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


def udp(src, dst, dport, sport=40000):
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)


def icmp(src, dst):
    return IP(src=src, dst=dst) / ICMP()


def feed(sensor, pkt, n=1):
    for _ in range(n):
        sensor.process_packet(pkt)


def types(log):
    return [a[0] for a in log]


# ================= helpers =================
@pytest.mark.parametrize("ip, expected", [
    ("224.0.0.251", True), ("239.255.255.250", True), ("192.168.1.255", True),
    ("10.0.0.5", False), ("223.1.1.1", False), ("garbage", False)])
def test_is_noise_dst(sensor, ip, expected):
    assert sensor.is_noise_dst(ip) is expected


def test_flow_key_is_the_same_in_both_directions(sensor):
    a = sensor.get_flow_key(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80))
    b = sensor.get_flow_key(IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1111))
    assert a[0] == b[0] and {a[1], b[1]} == {"fwd", "bwd"}


def test_flow_key_ignores_icmp_and_non_ip(sensor):
    assert sensor.get_flow_key(icmp("10.0.0.1", "10.0.0.2")) is None
    assert sensor.get_flow_key(ARP()) is None


def make_flow(**kw):
    flow = {"fwd_packets": [60, 60], "bwd_packets": [100], "start_time": 0.0, "last_time": 2.0,
            "init_win_fwd": 1000, "init_win_bwd": None, "dport": 80}
    flow.update(kw)
    return flow


def test_extract_features_numbers(sensor):
    f = sensor.extract_features(make_flow())
    assert f["Destination Port"] == 80
    assert f["Flow Duration"] == pytest.approx(2_000_000)
    assert f["Total Fwd Packets"] == 2 and f["Total Backward Packets"] == 1
    assert f["Total Length of Fwd Packets"] == 120
    assert f["Fwd Packet Length Max"] == 60 and f["Bwd Packet Length Max"] == 100
    assert f["Flow Packets/s"] == pytest.approx(1.5)
    assert f["Flow Bytes/s"] == pytest.approx(110)           # 220 bytes in 2 s
    assert f["Down/Up Ratio"] == pytest.approx(0.5)
    assert f["Init_Win_bytes_forward"] == 1000 and f["Init_Win_bytes_backward"] == 0


def test_extract_features_one_way_and_instant_flow(sensor):
    f = sensor.extract_features(make_flow(bwd_packets=[], start_time=5.0, last_time=5.0))
    assert f["Flow Duration"] == 1                            # never zero: no divide-by-zero
    assert f["Down/Up Ratio"] == 0 and f["Bwd Packet Length Max"] == 0


# ================= detectors (called directly) =================
def test_port_scan_needs_10_distinct_ports(sensor, clock, alerts_log):
    for p in range(1, 10):
        assert sensor.check_port_scan("6.6.6.6", p) is False
    assert alerts_log == []
    assert sensor.check_port_scan("6.6.6.6", 10) is True
    assert alerts_log == [("PortScan", "6.6.6.6", "-", "-", "10 ports in 5s")]
    sensor.check_port_scan("6.6.6.6", 11)                    # still scanning: no second alert
    assert len(alerts_log) == 1


def test_port_scan_ports_must_fall_inside_the_window(sensor, clock, alerts_log):
    for p in range(1, 21):                                   # one port per second, 5 s window
        sensor.check_port_scan("6.6.6.6", p)
        clock.advance(1)
    assert alerts_log == []


def test_repeating_one_port_is_not_a_scan(sensor, clock, alerts_log):
    for _ in range(50):
        assert sensor.check_port_scan("6.6.6.6", 80) is False
    assert alerts_log == []


def test_syn_flood_threshold_is_100(sensor, clock, alerts_log):
    for _ in range(99):
        assert sensor.check_dos_syn_flood("6.6.6.6", "10.0.0.5") is False
    assert sensor.check_dos_syn_flood("6.6.6.6", "10.0.0.5") is True
    assert alerts_log == [("DoS/SYN Flood", "6.6.6.6", "10.0.0.5", "any", "100 SYNs in 5s")]


def test_syn_flood_counts_each_source_separately(sensor, clock, alerts_log):
    for _ in range(60):
        sensor.check_dos_syn_flood("6.6.6.6", "10.0.0.5")
        sensor.check_dos_syn_flood("7.7.7.7", "10.0.0.5")
    assert alerts_log == []


def test_syn_flood_can_alert_again_after_it_stops(sensor, clock, alerts_log):
    for _ in range(100):
        sensor.check_dos_syn_flood("6.6.6.6", "10.0.0.5")
    assert len(alerts_log) == 1
    clock.advance(10)
    sensor.check_dos_syn_flood("6.6.6.6", "10.0.0.5")        # quiet again: flag is cleared
    for _ in range(99):
        sensor.check_dos_syn_flood("6.6.6.6", "10.0.0.5")
    assert len(alerts_log) == 2


def test_brute_force_needs_8_syns_to_a_service_port(sensor, clock, alerts_log):
    for _ in range(7):
        assert sensor.check_brute_force("6.6.6.6", "10.0.0.5", 22) is False
    assert sensor.check_brute_force("6.6.6.6", "10.0.0.5", 22) is True
    assert alerts_log == [("BruteForce", "6.6.6.6", "10.0.0.5", 22, "8 SYNs in 10s")]


def test_brute_force_ignores_non_service_ports(sensor, clock, alerts_log):
    for _ in range(50):
        assert sensor.check_brute_force("6.6.6.6", "10.0.0.5", 4444) is False
    assert alerts_log == []


def test_icmp_flood_threshold_is_100(sensor, clock, alerts_log):
    for _ in range(99):
        assert sensor.check_icmp_flood("6.6.6.6", "10.0.0.5") is False
    assert sensor.check_icmp_flood("6.6.6.6", "10.0.0.5") is True
    assert alerts_log == [("ICMP Flood", "6.6.6.6", "10.0.0.5", "-", "100 ICMP packets in 5s")]


def test_udp_flood_threshold_is_100(sensor, clock, alerts_log):
    for _ in range(99):
        assert sensor.check_udp_flood("6.6.6.6", "10.0.0.5", 5000) is False
    assert sensor.check_udp_flood("6.6.6.6", "10.0.0.5", 5000) is True
    assert alerts_log == [("UDP Flood", "6.6.6.6", "10.0.0.5", 5000, "100 UDP packets in 5s")]


# ================= whole packets through process_packet =================
def test_syn_flood_packets(sensor, clock, alerts_log):
    feed(sensor, tcp("6.6.6.6", "10.0.0.5", 5555), 99)
    assert alerts_log == []
    feed(sensor, tcp("6.6.6.6", "10.0.0.5", 5555))
    assert types(alerts_log) == ["DoS/SYN Flood"]
    assert alerts_log[0][1:4] == ("6.6.6.6", "10.0.0.5", "any")


def test_syn_ack_replies_are_not_counted(sensor, clock, alerts_log):
    feed(sensor, tcp("6.6.6.6", "10.0.0.5", 5555, flags="SA"), 200)
    assert alerts_log == []


def test_port_scan_packets(sensor, clock, alerts_log):
    for port in range(1000, 1010):
        feed(sensor, tcp("6.6.6.6", "10.0.0.5", port))
    assert types(alerts_log) == ["PortScan"]


def test_brute_force_packets(sensor, clock, alerts_log):
    feed(sensor, tcp("6.6.6.6", "10.0.0.5", 22), 8)
    assert types(alerts_log) == ["BruteForce"]
    assert alerts_log[0][3] == 22


def test_icmp_flood_packets(sensor, clock, alerts_log):
    feed(sensor, icmp("6.6.6.6", "10.0.0.5"), 100)
    assert types(alerts_log) == ["ICMP Flood"]


def test_udp_flood_packets(sensor, clock, alerts_log):
    feed(sensor, udp("6.6.6.6", "10.0.0.5", 5000), 100)
    assert types(alerts_log) == ["UDP Flood"]


def test_trusted_sources_never_alert(sensor, clock, alerts_log, monkeypatch):
    monkeypatch.setattr(sensor, "IGNORE_SRC", {"10.0.0.50"})
    feed(sensor, tcp("10.0.0.50", "10.0.0.5", 5555), 200)
    feed(sensor, icmp("10.0.0.50", "10.0.0.5"), 200)
    feed(sensor, udp("10.0.0.50", "10.0.0.5", 5000), 200)
    assert alerts_log == []


@pytest.mark.parametrize("dst, dport", [
    ("10.0.0.5", 53), ("10.0.0.5", 123), ("10.0.0.255", 5000), ("224.0.0.251", 5353)])
def test_normal_udp_chatter_is_ignored(sensor, clock, alerts_log, dst, dport):
    feed(sensor, udp("6.6.6.6", dst, dport), 150)
    assert alerts_log == []


def test_replies_to_our_own_udp_requests_are_not_a_flood(sensor, clock, alerts_log, monkeypatch):
    monkeypatch.setattr(sensor, "IGNORE_SRC", {"10.0.0.5"})             # this machine
    feed(sensor, udp("10.0.0.5", "8.8.8.8", 5000, sport=40000))         # we ask
    feed(sensor, udp("8.8.8.8", "10.0.0.5", 40000, sport=5000), 200)    # the server answers a lot
    assert alerts_log == []


def test_unsolicited_udp_flood_is_detected(sensor, clock, alerts_log):
    feed(sensor, udp("8.8.8.8", "10.0.0.5", 40000, sport=5000), 100)
    assert types(alerts_log) == ["UDP Flood"]


# ================= ML path =================
def test_ml_attack_raises_an_alert(sensor, clock, alerts_log):
    sensor.model.pred, sensor.model.conf = 1, 0.95
    feed(sensor, tcp("6.6.6.6", "10.0.0.5", 80, flags="A", sport=1234), 2)
    assert types(alerts_log) == ["ML-Detected"]
    assert "confidence=95%" in alerts_log[0][4]


def test_ml_low_confidence_is_ignored(sensor, clock, alerts_log):
    sensor.model.pred, sensor.model.conf = 1, 0.70
    feed(sensor, tcp("6.6.6.6", "10.0.0.5", 80, flags="A", sport=1234), 2)
    assert alerts_log == []


def test_ml_benign_prediction_is_silent(sensor, clock, alerts_log):
    sensor.model.pred = 0
    feed(sensor, tcp("6.6.6.6", "10.0.0.5", 80, flags="A", sport=1234), 5)
    assert alerts_log == []


def test_ml_alerts_on_dns_port_are_suppressed(sensor, clock, alerts_log):
    sensor.model.pred, sensor.model.conf = 1, 0.99
    feed(sensor, udp("6.6.6.6", "10.0.0.5", 53, sport=5000), 3)
    assert alerts_log == []


# ================= alert output =================
@pytest.fixture()
def real_log(sensor, clock, monkeypatch, tmp_path):
    """Uses the REAL log_alert, but writes the CSV in a temp folder and captures uploads."""
    monkeypatch.chdir(tmp_path)
    posted = []
    monkeypatch.setattr(sensor, "post_alert", posted.append)
    monkeypatch.setattr(sensor, "threading", SimpleNamespace(Thread=SyncThread))
    return posted


def test_log_alert_writes_csv_and_uploads(sensor, real_log, tmp_path):
    sensor.log_alert("DoS/SYN Flood", "6.6.6.6", "10.0.0.5", "any", "100 SYNs in 5s")
    rows = list(csv.reader((tmp_path / "alerts.csv").read_text().splitlines()))
    assert rows[0] == ["time", "type", "src", "dst", "dport", "detail"]
    assert rows[1][1:] == ["DoS/SYN Flood", "6.6.6.6", "10.0.0.5", "any", "100 SYNs in 5s"]
    assert real_log[0]["type"] == "DoS/SYN Flood" and real_log[0]["dport"] == "any"


def test_same_alert_is_logged_once_per_10_seconds(sensor, clock, real_log):
    for _ in range(3):
        sensor.log_alert("PortScan", "6.6.6.6", "-", "-", "x")
    assert len(real_log) == 1
    clock.advance(11)
    sensor.log_alert("PortScan", "6.6.6.6", "-", "-", "x")
    assert len(real_log) == 2
    sensor.log_alert("PortScan", "7.7.7.7", "-", "-", "x")   # different source
    assert len(real_log) == 3


def test_post_alert_sends_the_sensor_key(sensor, monkeypatch):
    seen = []
    monkeypatch.setattr(sensor, "SENSOR_KEY", "secret")
    monkeypatch.setattr(sensor.urllib.request, "urlopen",
                        lambda req, timeout=0: seen.append(req) or SimpleNamespace(close=lambda: None))
    sensor.post_alert({"type": "DoS"})
    assert seen[0].get_header("X-service-key") == "secret"
    assert json.loads(seen[0].data) == {"type": "DoS"}


def test_post_alert_does_nothing_without_a_key(sensor, monkeypatch):
    monkeypatch.setattr(sensor, "SENSOR_KEY", "")

    def boom(*a, **k):
        raise AssertionError("must not touch the network")
    monkeypatch.setattr(sensor.urllib.request, "urlopen", boom)
    sensor.post_alert({"type": "DoS"})


def test_post_alert_survives_a_dead_platform(sensor, monkeypatch):
    monkeypatch.setattr(sensor, "SENSOR_KEY", "secret")

    def down(*a, **k):
        raise OSError("platform down")
    monkeypatch.setattr(sensor.urllib.request, "urlopen", down)
    sensor.post_alert({"type": "DoS"})                       # must not raise


# ================= memory cleanup =================
def test_cleanup_drops_idle_flows_and_old_counters(sensor, clock, monkeypatch):
    sensor.process_packet(tcp("6.6.6.6", "10.0.0.5", 5555))
    assert len(sensor.flows) == 1 and "6.6.6.6" in sensor.dos_syn_tracker
    clock.advance(120)
    monkeypatch.setattr(sensor, "last_cleanup", 0)
    sensor.cleanup(clock.time())
    assert len(sensor.flows) == 0
    assert "6.6.6.6" not in sensor.dos_syn_tracker