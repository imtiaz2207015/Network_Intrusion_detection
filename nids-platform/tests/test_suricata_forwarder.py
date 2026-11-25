from datetime import datetime, timedelta
import importlib.util
import json
import pathlib
import jwt
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FWD_PATH = ROOT / "MachineLearningCVE" / "suricata_forwarder.py"


@pytest.fixture(scope="module")
def fwd():
    spec = importlib.util.spec_from_file_location("suricata_forwarder", FWD_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _eve_alert(
    signature,
    *,
    sid=2000001,
    category="Attempted Information Leak",
    severity=2,
    src_ip="198.51.100.42",
    dest_ip="192.168.1.50",
    dest_port=22,
    timestamp="2026-11-20T12:00:00.123456+0000",
    event_type="alert",
):
    return json.dumps({
        "timestamp": timestamp,
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": 54321,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": sid,
            "rev": 1,
            "signature": signature,
            "category": category,
            "severity": severity,
        },
    })


def _hdr(alert_mod, sub="1", username="alice", role="admin"):
    payload = {
        "sub": str(sub),
        "username": username,
        "role": role,
        "exp": datetime.now() + timedelta(hours=1),
    }
    tok = jwt.encode(payload, alert_mod.SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {tok}"}


def _sensor_key(alert_client, alert_mod, sub="1", username="alice"):
    h = _hdr(alert_mod, sub=sub, username=username)
    r = alert_client.get("/sensors/me", headers=h).get_json()
    if r.get("key"):
        return r["key"]
    return alert_client.post("/sensors/me/regenerate", headers=h).get_json()["key"]


@pytest.fixture()
def suri_alerts(alerts, monkeypatch):
    con = alerts.connect()
    con.cursor().execute(
        "TRUNCATE alerts, blocked_ips, allowlist, user_protection_settings, auto_block_audit, ai_explanations, ai_usage RESTART IDENTITY"
    )
    con.commit()
    con.close()
    monkeypatch.setattr(alerts, "EMAIL_ON", False)
    yield alerts
    if getattr(alerts, "LEGACY_SENSOR_KEY", None):
        con2 = alerts.connect()
        cur2 = con2.cursor()
        kh = alerts.hash_sensor_key(alerts.LEGACY_SENSOR_KEY)
        kp = alerts.LEGACY_SENSOR_KEY[:6]
        cur2.execute("UPDATE sensors SET key_hash=%s, key_prefix=%s WHERE owner_user_id=1", (kh, kp))
        con2.commit()
        con2.close()


# ---------- 1. Real Suricata sample lines & mapping ----------
def test_real_suricata_samples_and_decoder_filtering(fwd):
    local = {"192.168.1.50"}

    # Real ET SCAN samples across both observed categories -> all map to PortScan + Medium
    samples = [
        ("ET SCAN NMAP OS Detection Probe", "Attempted Information Leak", 2000536, 2),
        ("ET SCAN Potential SSH Scan", "Attempted Information Leak", 2001219, 2),
        ("ET SCAN Suspicious inbound to mySQL port 3306", "Potentially Bad Traffic", 2010937, 2),
    ]
    for sig, cat, sid, sev in samples:
        line = _eve_alert(sig, sid=sid, category=cat, severity=sev)
        ev = fwd.parse_eve_line(line, local_ips=local, forward_decoder_events=False, forward_test_rule=False)
        assert ev is not None
        assert ev["type"] == "PortScan"
        assert ev["severity"] == "Medium"
        assert ev["signature"] == sig
        assert ev["signature_id"] == sid
        assert ev["source"] == "suricata"
        assert ev["src"] == "198.51.100.42"
        assert ev["dst"] == "192.168.1.50"

    # Real decoder event: SURICATA ICMPv4 unknown code -> ignored by default
    dec_line = _eve_alert("SURICATA ICMPv4 unknown code", sid=2200024, category="Generic Protocol Command Decode", severity=3)
    assert fwd.parse_eve_line(dec_line, local_ips=local, forward_decoder_events=False) is None

    # Forwarded only when FORWARD_DECODER_EVENTS=1
    ev_dec = fwd.parse_eve_line(dec_line, local_ips=local, forward_decoder_events=True)
    assert ev_dec is not None
    assert ev_dec["type"] == "SURICATA ICMPv4 unknown code"
    assert ev_dec["severity"] == "Low"


def test_category_severity_mapping_and_outbound_label_only(fwd):
    local = {"192.168.1.50"}

    # Denial of Service -> DoS, severity 1 -> High
    ev_dos = fwd.parse_eve_line(
        _eve_alert("ET DOS Flood", category="Attempted Denial of Service", severity=1),
        local_ips=local,
    )
    assert ev_dos["type"] == "DoS" and ev_dos["severity"] == "High"

    # Web application attack + severity 1 -> Web Attack, Critical
    ev_web = fwd.parse_eve_line(
        _eve_alert("ET WEB_SERVER SQLi", category="Web Application Attack", severity=1),
        local_ips=local,
    )
    assert ev_web["type"] == "Web Attack" and ev_web["severity"] == "Critical"

    # Trojan + severity 1 -> Malware, Critical
    ev_troj = fwd.parse_eve_line(
        _eve_alert("ET TROJAN Bad Beacon", category="A Network Trojan was detected", severity=1),
        local_ips=local,
    )
    assert ev_troj["type"] == "Malware" and ev_troj["severity"] == "Critical"

    # Exploit / admin privilege gain + severity 1 -> Critical, type falls back to signature name
    ev_exp = fwd.parse_eve_line(
        _eve_alert("ET EXPLOIT Buffer Overflow", category="Attempted Administrator Privilege Gain", severity=1),
        local_ips=local,
    )
    assert ev_exp["type"] == "ET EXPLOIT Buffer Overflow" and ev_exp["severity"] == "Critical"

    # OUTBOUND in signature is label-only: src_ip and dest_ip MUST NOT be swapped
    ev_out = fwd.parse_eve_line(
        _eve_alert(
            "ET SCAN Potential SSH Scan OUTBOUND",
            category="Attempted Information Leak",
            severity=2,
            src_ip="198.51.100.77",
            dest_ip="192.168.1.50",
            dest_port=22,
        ),
        local_ips=local,
    )
    assert ev_out["type"] == "PortScan"
    assert ev_out["src"] == "198.51.100.77"
    assert ev_out["dst"] == "192.168.1.50"


def test_test_rule_ignore_loopback_own_ip_and_bad_json(fwd):
    local = {"192.168.1.50"}

    # Non-alert eve events are ignored
    assert fwd.parse_eve_line(json.dumps({"event_type": "flow", "src_ip": "198.51.100.1"}), local_ips=local) is None

    # Bad JSON never crashes
    assert fwd.parse_eve_line("{not valid json", local_ips=local) is None
    assert fwd.parse_eve_line("", local_ips=local) is None

    # SID 1000001 ignored by default, forwarded if FORWARD_TEST_RULE=1
    test_line = _eve_alert("Local Test Rule", sid=1000001, category="Misc Activity", severity=3)
    assert fwd.parse_eve_line(test_line, local_ips=local, forward_test_rule=False) is None
    ev_t = fwd.parse_eve_line(test_line, local_ips=local, forward_test_rule=True)
    assert ev_t is not None and ev_t["signature_id"] == 1000001

    # Loopback and Pi's own IP are never forwarded
    assert fwd.parse_eve_line(_eve_alert("ET SCAN Test", src_ip="127.0.0.1"), local_ips=local) is None
    assert fwd.parse_eve_line(_eve_alert("ET SCAN Test", src_ip="192.168.1.50"), local_ips=local) is None


# ---------- 2. Grouping, rate cap, rotation, and retry queue ----------
def test_grouping_merges_et_scan_burst_and_enforces_60s_per_group(fwd):
    local = {"192.168.1.50"}
    grouper = fwd.AlertGrouper(window_sec=60.0, coalesce_sec=2.0)

    burst = [
        _eve_alert("ET SCAN NMAP OS Detection Probe", sid=2000536, category="Attempted Information Leak", severity=2),
        _eve_alert("ET SCAN Potential SSH Scan", sid=2001219, category="Attempted Information Leak", severity=2),
        _eve_alert("ET SCAN Suspicious inbound to mySQL port 3306", sid=2010937, category="Potentially Bad Traffic", severity=2),
        _eve_alert("ET SCAN NMAP -sS window 1024", sid=2009582, category="Attempted Information Leak", severity=2),
    ]
    for line in burst:
        ev = fwd.parse_eve_line(line, local_ips=local)
        grouper.add(ev, now=100.0)

    # Before coalesce delay -> nothing flushed yet
    assert grouper.flush_ready(now=101.0) == []

    # After coalesce delay -> 1 merged alert with count=4 and first 3 signatures
    ready = grouper.flush_ready(now=102.5)
    assert len(ready) == 1
    p = ready[0]
    assert p["type"] == "PortScan"
    assert p["source"] == "suricata"
    assert p["detail"].startswith("4 merged signatures:")
    assert "ET SCAN NMAP OS Detection Probe" in p["detail"]
    assert "ET SCAN Potential SSH Scan" in p["detail"]
    assert "ET SCAN Suspicious inbound to mySQL port 3306" in p["detail"]
    assert "ET SCAN NMAP -sS window 1024" not in p["detail"]  # only first 3 names

    # Another alert in the same (src_ip, PortScan) group 10s later -> held until 60s window passes
    ev_later = fwd.parse_eve_line(burst[0], local_ips=local)
    grouper.add(ev_later, now=112.5)
    assert grouper.flush_ready(now=150.0) == []
    ready2 = grouper.flush_ready(now=163.0)
    assert len(ready2) == 1


def test_global_rate_cap_30_per_minute_and_drop_count(fwd):
    rl = fwd.RateLimiter(max_per_minute=30)
    allowed = sum(1 for i in range(35) if rl.allow(now=1000.0 + i * 0.1))
    assert allowed == 30
    assert rl.total_dropped == 5

    # After 61 seconds, window clears and posts are allowed again
    assert rl.allow(now=1065.0) is True


def test_tailer_starts_at_eof_tracks_state_and_handles_rotation(fwd, tmp_path):
    eve = tmp_path / "eve.json"
    state = tmp_path / "state.json"

    # Pre-existing historical line before first run -> should be skipped (start at EOF)
    eve.write_text(_eve_alert("ET SCAN Old Line") + "\n", encoding="utf-8")

    t1 = fwd.EveTailer(str(eve), str(state))
    assert t1.read_lines() == []

    # Append a new line -> read once
    with open(eve, "a", encoding="utf-8") as f:
        f.write(_eve_alert("ET SCAN Live Line 1") + "\n")
    lines = t1.read_lines()
    assert len(lines) == 1 and "Live Line 1" in lines[0]
    t1.close()

    # Restart tailer with same state file -> resumes at saved offset, does not replay Line 1
    with open(eve, "a", encoding="utf-8") as f:
        f.write(_eve_alert("ET SCAN Live Line 2") + "\n")
    t2 = fwd.EveTailer(str(eve), str(state))
    lines2 = t2.read_lines()
    assert len(lines2) == 1 and "Live Line 2" in lines2[0]

    # Simulate log rotation (rename old file + create new eve.json with new inode / smaller size)
    rotated = tmp_path / "eve.json.1"
    t2.close()
    eve.replace(rotated)
    eve.write_text(_eve_alert("ET SCAN After Rotation") + "\n", encoding="utf-8")

    lines3 = t2.read_lines()
    assert len(lines3) == 1 and "After Rotation" in lines3[0]
    t2.close()


def test_forwarder_bounded_queue_and_retry_backoff(fwd, tmp_path):
    eve = tmp_path / "eve.json"
    state = tmp_path / "state.json"
    eve.write_text("", encoding="utf-8")

    attempts = {"count": 0, "fail": True}
    delivered = []

    def flaky_poster(payload):
        attempts["count"] += 1
        if attempts["fail"]:
            raise OSError("connection refused")
        delivered.append(payload)
        return True

    f = fwd.SuricataForwarder(
        platform_url="http://127.0.0.1:8088",
        sensor_key="dummy-key",
        eve_path=str(eve),
        state_path=str(state),
        local_ips={"192.168.1.50"},
        group_coalesce_sec=0.0,
        max_queue_size=500,
        poster=flaky_poster,
    )
    # Prime tailer at EOF
    f.poll_once(now=10.0)

    # Append valid + bad JSON lines
    with open(eve, "a", encoding="utf-8") as fh:
        fh.write("not json at all\n")
        fh.write(_eve_alert("ET SCAN NMAP OS Detection Probe", src_ip="198.51.100.88") + "\n")

    # First poll fails -> alert stays queued, backoff set
    assert f.poll_once(now=11.0, force_flush=True) == 0
    assert len(f.queue) == 1
    assert attempts["count"] == 1

    # Immediate retry within backoff window -> skipped
    assert f.poll_once(now=11.2) == 0
    assert attempts["count"] == 1

    # Platform recovers after backoff -> queued alert is delivered
    attempts["fail"] = False
    assert f.poll_once(now=13.0) == 1
    assert len(f.queue) == 0
    assert len(delivered) == 1
    assert delivered[0]["type"] == "PortScan"
    f.tailer.close()


# ---------- 3. Platform (alert-service) Suricata integration tests ----------
def test_platform_ingest_list_source_filter_details_explain_and_isolation(suri_alerts, alert_client):
    h1 = _hdr(suri_alerts, sub="1", username="alice")
    h2 = _hdr(suri_alerts, sub="2", username="bob")
    k1 = _sensor_key(alert_client, suri_alerts, sub="1", username="alice")
    k2 = _sensor_key(alert_client, suri_alerts, sub="2", username="bob")

    # 1. Ingest legacy sensor alert (without source/signature/signature_id)
    r_old = alert_client.post(
        "/ingest",
        headers={"X-Service-Key": k1},
        json={"type": "PortScan", "src": "198.51.100.1", "dst": "10.0.0.5", "dport": "80", "detail": "12 ports in 5s"},
    )
    assert r_old.status_code == 201
    old_id = r_old.get_json()["id"]

    # 2. Ingest Suricata alert (with source='suricata', signature, signature_id)
    r_suri = alert_client.post(
        "/ingest",
        headers={"X-Service-Key": k1},
        json={
            "type": "PortScan",
            "src": "198.51.100.2",
            "dst": "10.0.0.5",
            "dport": "22",
            "detail": "3 merged signatures: ET SCAN NMAP OS Detection Probe",
            "source": "suricata",
            "signature": "ET SCAN NMAP OS Detection Probe",
            "signature_id": 2000536,
        },
    )
    assert r_suri.status_code == 201
    suri_id = r_suri.get_json()["id"]

    # 3. User 2 ingests their own Suricata alert (for per-user isolation check)
    r_u2 = alert_client.post(
        "/ingest",
        headers={"X-Service-Key": k2},
        json={
            "type": "Web Attack",
            "src": "203.0.113.99",
            "dst": "10.0.0.9",
            "dport": "443",
            "detail": "1 merged signature: ET WEB_SERVER SQLi",
            "source": "suricata",
            "signature": "ET WEB_SERVER SQLi",
            "signature_id": 2010001,
        },
    )
    assert r_u2.status_code == 201

    # 4. List & details return new fields accurately
    all_u1 = alert_client.get("/", headers=h1).get_json()
    assert all_u1["total"] == 2
    by_id = {a["id"]: a for a in all_u1["alerts"]}
    assert by_id[old_id]["source"] == "sensor"
    assert by_id[old_id]["signature"] is None
    assert by_id[old_id]["signature_id"] is None

    assert by_id[suri_id]["source"] == "suricata"
    assert by_id[suri_id]["signature"] == "ET SCAN NMAP OS Detection Probe"
    assert by_id[suri_id]["signature_id"] == 2000536

    det = alert_client.get(f"/{suri_id}", headers=h1).get_json()
    assert det["source"] == "suricata"
    assert det["signature"] == "ET SCAN NMAP OS Detection Probe"
    assert det["signature_id"] == 2000536

    # 5. Source filter (?source=suricata and ?source=sensor)
    only_suri = alert_client.get("/?source=suricata", headers=h1).get_json()
    assert only_suri["total"] == 1 and only_suri["alerts"][0]["id"] == suri_id

    only_sensor = alert_client.get("/?source=sensor", headers=h1).get_json()
    assert only_sensor["total"] == 1 and only_sensor["alerts"][0]["id"] == old_id

    # 6. Per-user isolation: User 2 cannot see User 1's Suricata alert
    assert alert_client.get(f"/{suri_id}", headers=h2).status_code == 404
    u2_list = alert_client.get("/?source=suricata", headers=h2).get_json()
    assert u2_list["total"] == 1 and u2_list["alerts"][0]["src"] == "203.0.113.99"

    # 7. AI Explain prompt includes signature, signature_id, and Suricata note
    prompt_suri = suri_alerts.build_explain_prompt(det)
    assert "Suricata" in prompt_suri
    assert "ET SCAN NMAP OS Detection Probe" in prompt_suri
    assert "2000536" in prompt_suri

    prompt_old = suri_alerts.build_explain_prompt(by_id[old_id])
    assert "Suricata" not in prompt_old

    # 8. Auto-block treats Suricata Critical/High alerts like any other alert (3 DoS alerts -> auto-blocked)
    for _ in range(3):
        alert_client.post(
            "/ingest",
            headers={"X-Service-Key": k1},
            json={
                "type": "DoS",
                "src": "198.51.100.77",
                "dst": "10.0.0.5",
                "dport": "80",
                "source": "suricata",
                "signature": "ET DOS SYN Flood",
                "signature_id": 2100001,
            },
        )
    blks = alert_client.get("/blocked-ips", headers=h1).get_json()["blocked"]
    assert any(b["ip"] == "198.51.100.77" and b["source"] == "auto" for b in blks)


def test_drain_queue_http_error_handling_401_400_and_5xx(fwd, tmp_path, caplog):
    import urllib.error

    eve = tmp_path / "eve.json"
    state = tmp_path / "state.json"
    eve.write_text("", encoding="utf-8")

    def make_http_err(code):
        return urllib.error.HTTPError(
            "http://127.0.0.1:8088/api/alerts/ingest",
            code,
            f"HTTP {code}",
            hdrs=None,
            fp=None,
        )

    # 1. 401 keeps the payload, backs off >= 30s, logs clear error without printing key
    secret_key = "SUPER-SECRET-SENSOR-KEY-999"
    f401 = fwd.SuricataForwarder(
        sensor_key=secret_key,
        eve_path=str(eve),
        state_path=str(state),
        poster=lambda p: (_ for _ in ()).throw(make_http_err(401)),
    )
    f401.enqueue({"type": "PortScan", "src": "198.51.100.10"})
    with caplog.at_level("ERROR", logger="suricata_forwarder"):
        assert f401.drain_queue(now=100.0) == 0
    assert len(f401.queue) == 1
    assert f401._next_retry_at >= 130.0
    assert any("sensor key rejected, check SENSOR_KEY" in rec.message for rec in caplog.records)
    assert all(secret_key not in rec.message for rec in caplog.records)
    # Second 401 doubles backoff up to 300s
    assert f401.drain_queue(now=135.0) == 0
    assert f401._next_retry_at >= 195.0
    assert f401._backoff_sec <= 300.0

    # 2. 400 drops invalid payload so subsequent valid payload is still sent
    delivered = []
    calls = {"n": 0}

    def poster_400_then_ok(p):
        calls["n"] += 1
        if calls["n"] == 1:
            raise make_http_err(400)
        delivered.append(p)
        return True

    f400 = fwd.SuricataForwarder(
        sensor_key="k",
        eve_path=str(eve),
        state_path=str(state),
        poster=poster_400_then_ok,
    )
    f400.enqueue({"type": "Bad", "src": "198.51.100.1"})
    f400.enqueue({"type": "PortScan", "src": "198.51.100.2"})
    assert f400.drain_queue(now=200.0) == 1
    assert len(f400.queue) == 0
    assert len(delivered) == 1 and delivered[0]["src"] == "198.51.100.2"

    # 3. 5xx keeps payload in queue and retries with backoff
    state_5xx = {"fail": True}
    sent_5xx = []

    def poster_503_then_ok(p):
        if state_5xx["fail"]:
            raise make_http_err(503)
        sent_5xx.append(p)
        return True

    f5xx = fwd.SuricataForwarder(
        sensor_key="k",
        eve_path=str(eve),
        state_path=str(state),
        poster=poster_503_then_ok,
    )
    f5xx.enqueue({"type": "DoS", "src": "198.51.100.3"})
    assert f5xx.drain_queue(now=300.0) == 0
    assert len(f5xx.queue) == 1
    assert f5xx._next_retry_at == 301.0
    state_5xx["fail"] = False
    assert f5xx.drain_queue(now=301.5) == 1
    assert len(f5xx.queue) == 0 and len(sent_5xx) == 1


def test_alert_grouper_bounded_after_10000_events(fwd):
    grouper = fwd.AlertGrouper(window_sec=60.0, coalesce_sec=2.0)
    for i in range(10000):
        ev = {
            "time": "2026-11-20 12:00:00",
            "type": "PortScan",
            "src": "198.51.100.50",
            "dst": "192.168.1.50",
            "dport": "22",
            "signature": f"ET SCAN Sig {i % 20}",
            "signature_id": 2000000 + (i % 20),
            "category": "Attempted Information Leak",
            "severity": "Medium",
            "source": "suricata",
        }
        grouper.add(ev, now=100.0)

    bucket = grouper._pending[("198.51.100.50", "PortScan")]
    assert "events" not in bucket
    assert bucket["count"] == 10000
    assert len(bucket["signatures"]) == 5

    ready = grouper.flush_ready(now=103.0)
    assert len(ready) == 1
    assert ready[0]["detail"].startswith("10000 merged signatures: ET SCAN Sig 0; ET SCAN Sig 1; ET SCAN Sig 2")
