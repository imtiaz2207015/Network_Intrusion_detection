from datetime import datetime, timedelta, timezone
import time
import jwt
import pytest


def token_for(secret, sub="1", username="tester", role="admin"):
    payload = {
        "sub": str(sub),
        "username": username,
        "role": role,
        "exp": datetime.now() + timedelta(hours=1),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def hdr_for(alert_mod, sub="1", username="tester", role="admin"):
    return {"Authorization": f"Bearer {token_for(alert_mod.SECRET, sub=sub, username=username, role=role)}"}


def sensor_key_for(alert_client, alert_mod, sub="1", username="tester"):
    h = hdr_for(alert_mod, sub=sub, username=username)
    r = alert_client.get("/sensors/me", headers=h).get_json()
    if r.get("key"):
        return r["key"]
    r2 = alert_client.post("/sensors/me/regenerate", headers=h).get_json()
    return r2["key"]


@pytest.fixture()
def prot(alerts, monkeypatch):
    con = alerts.connect()
    con.cursor().execute(
        "TRUNCATE alerts, blocked_ips, allowlist, user_protection_settings, auto_block_audit, email_throttle, sensor_status RESTART IDENTITY"
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


def test_default_is_auto_and_validation(prot, alert_client):
    assert alert_client.get("/protection").status_code == 401
    assert alert_client.put("/protection", json={"mode": "manual"}).status_code == 401
    assert alert_client.get("/auto-block/audit").status_code == 401

    h = hdr_for(prot, sub="1", username="alice")
    d = alert_client.get("/protection", headers=h).get_json()
    assert d == {
        "user_id": 1,
        "mode": "auto",
    }

    # Invalid values -> 400
    for bad in (
        {},
        {"mode": "invalid"},
        {"mode": ""},
        {"mode": None},
    ):
        assert alert_client.put("/protection", json=bad, headers=h).status_code == 400

    # Valid updates -> 200 (only mode is returned and stored; legacy fields are ignored)
    upd = alert_client.put(
        "/protection",
        json={"mode": "manual", "threshold_count": 99},
        headers=h,
    )
    assert upd.status_code == 200
    assert upd.get_json() == {"user_id": 1, "mode": "manual"}

    upd2 = alert_client.put("/protection", json={"mode": "auto"}, headers=h)
    assert upd2.status_code == 200
    assert upd2.get_json() == {"user_id": 1, "mode": "auto"}


def test_manual_mode_never_auto_blocks_and_manual_durations_work(prot, alert_client):
    h = hdr_for(prot, sub="1", username="alice")
    skey = sensor_key_for(alert_client, prot, sub="1", username="alice")

    # Switch to manual mode
    assert alert_client.put("/protection", json={"mode": "manual"}, headers=h).status_code == 200

    for _ in range(5):
        r = alert_client.post(
            "/ingest",
            headers={"X-Service-Key": skey},
            json={"type": "DoS/SYN Flood", "src": "198.51.100.20", "dst": "10.0.0.5", "dport": "80"},
        )
        assert r.status_code == 201

    # No automatic block created
    blks = alert_client.get("/blocked-ips", headers=h).get_json()["blocked"]
    assert blks == []

    # Manual Block IP supports 1h (60m), 24h (1440m), 7d (10080m), and Until I unblock (0 / None)
    aid = alert_client.get("/", headers=h).get_json()["alerts"][0]["id"]
    for idx, (mins, expected_sec) in enumerate([(60, 3600), (1440, 86400), (10080, 604800), (0, None)]):
        ip = f"198.51.100.{30 + idx}"
        mb = alert_client.post("/block-ip", json={"ip": ip, "alert_id": aid, "minutes": mins}, headers=h)
        assert mb.status_code == 201
        mb_data = mb.get_json()
        assert mb_data["source"] == "manual"
        assert mb_data["seconds_left"] == expected_sec
        assert alert_client.post(f"/blocked-ips/{mb_data['id']}/unblock", headers=h).status_code == 200


def test_fixed_thresholds_and_repeat_offender_escalation_1h_24h_7d(prot, alert_client, monkeypatch):
    h = hdr_for(prot, sub="1", username="alice")
    skey = sensor_key_for(alert_client, prot, sub="1", username="alice")

    sent_emails = []
    monkeypatch.setattr(prot, "EMAIL_ON", True)
    monkeypatch.setattr(prot, "get_owner_email", lambda uid: f"user{uid}@example.com")
    monkeypatch.setattr(
        prot,
        "dispatch_mail",
        lambda to_e, subj, body, html_body=None: sent_emails.append({"to": to_e, "subject": subj, "body": body, "html": html_body}),
    )

    # 1. Medium severity (PortScan) is below fixed min_severity='High' -> never auto-blocks
    for _ in range(4):
        alert_client.post(
            "/ingest",
            headers={"X-Service-Key": skey},
            json={"type": "PortScan", "src": "198.51.100.10", "dst": "10.0.0.5", "dport": "-"},
        )
    assert alert_client.get("/blocked-ips", headers=h).get_json()["blocked"] == []

    # 2. First time: 3 BruteForce (High) alerts in 10 min -> blocked for 60 minutes (1 hour)
    for _ in range(2):
        alert_client.post(
            "/ingest",
            headers={"X-Service-Key": skey},
            json={"type": "BruteForce", "src": "198.51.100.10", "dst": "10.0.0.5", "dport": "22"},
        )
    assert alert_client.get("/blocked-ips", headers=h).get_json()["blocked"] == []

    r3 = alert_client.post(
        "/ingest",
        headers={"X-Service-Key": skey},
        json={"type": "BruteForce", "src": "198.51.100.10", "dst": "10.0.0.5", "dport": "22"},
    )
    aid3 = r3.get_json()["id"]
    blks = alert_client.get("/blocked-ips", headers=h).get_json()["blocked"]
    assert len(blks) == 1
    b1 = blks[0]
    assert b1["ip"] == "198.51.100.10"
    assert b1["source"] == "auto"
    assert b1["reason"] == "BruteForce x3 in 10 min"
    assert b1["alert_id"] == aid3
    assert 3500 <= b1["seconds_left"] <= 3600
    assert len(sent_emails) == 1

    # Unblock so the attacker can offend again
    assert alert_client.post(f"/blocked-ips/{b1['id']}/unblock", headers=h).status_code == 200

    # 3. Second offense within 24 hours -> escalated to 24 hours (1440 min = 86400 s)
    alert_client.post(
        "/ingest",
        headers={"X-Service-Key": skey},
        json={"type": "BruteForce", "src": "198.51.100.10", "dst": "10.0.0.5", "dport": "22"},
    )
    active2 = [r for r in alert_client.get("/blocked-ips", headers=h).get_json()["blocked"] if r["status"] == "active"]
    assert len(active2) == 1
    b2 = active2[0]
    assert b2["reason"] == "BruteForce x4 in 10 min (repeat offender, 24 h)"
    assert 86300 <= b2["seconds_left"] <= 86400

    # Unblock and add a 3rd historical block within the last 7 days
    assert alert_client.post(f"/blocked-ips/{b2['id']}/unblock", headers=h).status_code == 200
    two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
    con = prot.connect()
    con.cursor().execute(
        """INSERT INTO blocked_ips(ip, status, blocked_by, blocked_at, owner_user_id, source, reason)
           VALUES('198.51.100.10', 'expired', 'auto', %s, 1, 'auto', 'Earlier offense')""",
        (two_days_ago,),
    )
    con.commit()
    con.close()

    # 4. Now the IP has >= 3 previous blocks within 7 days -> next offense blocks for 7 days (10080 min = 604800 s)
    alert_client.post(
        "/ingest",
        headers={"X-Service-Key": skey},
        json={"type": "BruteForce", "src": "198.51.100.10", "dst": "10.0.0.5", "dport": "22"},
    )
    active3 = [r for r in alert_client.get("/blocked-ips", headers=h).get_json()["blocked"] if r["status"] == "active"]
    assert len(active3) == 1
    b3 = active3[0]
    assert b3["reason"] == "BruteForce x5 in 10 min (repeat offender, 7 d)"
    assert 604700 <= b3["seconds_left"] <= 604800


def test_allowlist_protected_ips_duplicate_skip_and_cap_eviction(prot, alert_client, monkeypatch):
    h = hdr_for(prot, sub="1", username="alice")
    skey = sensor_key_for(alert_client, prot, sub="1", username="alice")

    # Default cap is 100
    assert prot.BLOCK_MAX_ACTIVE == 100

    # 1. Register sensor_ip and gateway_ip via heartbeat, plus an allowlisted IP and PLATFORM_HOST_IP
    monkeypatch.setenv("PLATFORM_HOST_IP", "198.51.100.250")
    alert_client.post(
        "/heartbeat",
        headers={"X-Service-Key": skey},
        json={"host": "pi5", "packets": 10, "uptime": 5, "sensor_ip": "198.51.100.251", "gateway_ip": "198.51.100.1"},
    )
    con = prot.connect()
    con.cursor().execute(
        "INSERT INTO allowlist(owner_user_id, ip, created_at) VALUES(1, '198.51.100.55', '2026-11-19 00:00:00')"
    )
    con.commit()
    con.close()

    # None of loopback, gateway, sensor's own IP, platform host, or allowlist are ever blocked
    for protected_ip in ("127.0.0.1", "198.51.100.1", "198.51.100.251", "198.51.100.250", "198.51.100.55"):
        for _ in range(3):
            alert_client.post(
                "/ingest",
                headers={"X-Service-Key": skey},
                json={"type": "BruteForce", "src": protected_ip, "dst": "10.0.0.5", "dport": "22"},
            )
    assert alert_client.get("/blocked-ips", headers=h).get_json()["blocked"] == []

    # 2. Duplicate skip: block 198.51.100.60 via 3 alerts, then send 4th alert -> skipped as duplicate
    for _ in range(4):
        alert_client.post(
            "/ingest",
            headers={"X-Service-Key": skey},
            json={"type": "BruteForce", "src": "198.51.100.60", "dst": "10.0.0.5", "dport": "22"},
        )
    blks = alert_client.get("/blocked-ips", headers=h).get_json()["blocked"]
    assert len(blks) == 1
    audit = alert_client.get("/auto-block/audit", headers=h).get_json()["audit"]
    assert audit[0]["action"] == "skipped" and "already blocked" in audit[0]["reason"].lower()

    # 3. Cap eviction: when active blocks reach BLOCK_MAX_ACTIVE, evicts the block closest to expiring, logs in audit, and continues
    monkeypatch.setattr(prot, "BLOCK_MAX_ACTIVE", 2)

    # Add a second active block (198.51.100.61) and make 198.51.100.60 closer to expiring than 198.51.100.61
    for _ in range(3):
        alert_client.post(
            "/ingest",
            headers={"X-Service-Key": skey},
            json={"type": "BruteForce", "src": "198.51.100.61", "dst": "10.0.0.5", "dport": "22"},
        )
    now_t = time.time()
    con = prot.connect()
    con.cursor().execute("UPDATE blocked_ips SET expires_at=%s WHERE ip='198.51.100.60'", (now_t + 120,))
    con.cursor().execute("UPDATE blocked_ips SET expires_at=%s WHERE ip='198.51.100.61'", (now_t + 3000,))
    con.commit()
    con.close()

    # Now active count == 2 (at cap). Ingesting 3 alerts for 198.51.100.62 must evict 198.51.100.60 (closest to expiring) and block 198.51.100.62
    for _ in range(3):
        alert_client.post(
            "/ingest",
            headers={"X-Service-Key": skey},
            json={"type": "BruteForce", "src": "198.51.100.62", "dst": "10.0.0.5", "dport": "22"},
        )

    all_blks = alert_client.get("/blocked-ips", headers=h).get_json()["blocked"]
    by_ip = {r["ip"]: r["status"] for r in all_blks}
    assert by_ip["198.51.100.60"] == "expired"
    assert by_ip["198.51.100.61"] == "active"
    assert by_ip["198.51.100.62"] == "active"

    audit_after = alert_client.get("/auto-block/audit", headers=h).get_json()["audit"]
    evicted_rows = [a for a in audit_after if a["action"] == "evicted"]
    assert len(evicted_rows) == 1
    assert evicted_rows[0]["ip"] == "198.51.100.60"


def test_per_user_isolation_for_protection_and_audit(prot, alert_client):
    h_a = hdr_for(prot, sub="10", username="user_a")
    h_b = hdr_for(prot, sub="20", username="user_b")
    skey_a = sensor_key_for(alert_client, prot, sub="10", username="user_a")
    skey_b = sensor_key_for(alert_client, prot, sub="20", username="user_b")

    # User A sets manual mode; User B keeps default auto mode
    assert alert_client.put("/protection", json={"mode": "manual"}, headers=h_a).status_code == 200
    assert alert_client.get("/protection", headers=h_a).get_json()["mode"] == "manual"
    assert alert_client.get("/protection", headers=h_b).get_json()["mode"] == "auto"

    for _ in range(3):
        alert_client.post(
            "/ingest",
            headers={"X-Service-Key": skey_a},
            json={"type": "BruteForce", "src": "198.51.100.88", "dst": "10.0.0.5", "dport": "22"},
        )
        alert_client.post(
            "/ingest",
            headers={"X-Service-Key": skey_b},
            json={"type": "BruteForce", "src": "198.51.100.88", "dst": "10.0.0.5", "dport": "22"},
        )

    # User A has 0 blocks and 0 audit rows; User B has 1 auto block and 3 audit rows
    assert alert_client.get("/blocked-ips", headers=h_a).get_json()["blocked"] == []
    assert alert_client.get("/auto-block/audit", headers=h_a).get_json()["audit"] == []

    b_blks = alert_client.get("/blocked-ips", headers=h_b).get_json()["blocked"]
    assert len(b_blks) == 1 and b_blks[0]["source"] == "auto"


def test_sensor_popup_alert_level_default_and_update(prot, alert_client):
    h = hdr_for(prot, sub="1", username="alice")
    me = alert_client.get("/sensors/me", headers=h).get_json()
    assert me["popup_alert_level"] == "critical_high"

    bad = alert_client.patch("/sensors/me", json={"popup_alert_level": "invalid"}, headers=h)
    assert bad.status_code == 400

    for lv in ("critical", "off", "critical_high"):
        upd = alert_client.patch("/sensors/me", json={"popup_alert_level": lv}, headers=h)
        assert upd.status_code == 200
        assert upd.get_json()["popup_alert_level"] == lv
