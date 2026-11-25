"""
Automated verification of critical-alert email throttling, per-owner caps,
friendly attack names, alert_email_level preference, cross-owner email isolation,
and DB persistence across restarts in alert-service/app.py.
"""
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import pathlib
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

from conftest import make_fake_flask

ROOT = pathlib.Path(__file__).resolve().parent.parent


class PyJWTError(Exception):
    pass


def _jwt_encode(payload, secret, algorithm="HS256"):
    p = dict(payload)
    if "exp" in p and hasattr(p["exp"], "timestamp"):
        p["exp"] = int(p["exp"].timestamp())
    body = base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip("=")
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"hdr.{body}.{sig}"


def _jwt_decode(token, secret, algorithms=None):
    parts = token.split(".")
    if len(parts) != 3:
        raise PyJWTError("bad token")
    _, body, sig = parts
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise PyJWTError("bad signature")
    pad = "=" * (-len(body) % 4)
    return json.loads(base64.urlsafe_b64decode(body + pad).decode())


def _make_fake_jwt():
    fake_jwt = types.ModuleType("jwt")
    fake_jwt.PyJWTError = PyJWTError
    fake_jwt.encode = _jwt_encode
    fake_jwt.decode = _jwt_decode
    return fake_jwt


LOG_LINES = []


class PersistentDB:
    def __init__(self):
        self.users = {
            10: {"id": 10, "username": "owner_a", "email": "owner_a@example.com"},
            20: {"id": 20, "username": "owner_b", "email": "owner_b@example.com"},
        }
        self.sensors = []
        self.alerts = []
        self.sensor_status = []
        self.email_throttle = {}
        self.next_sensor_id = 1
        self.next_alert_id = 1


DB = PersistentDB()


class FakeCursor:
    def __init__(self):
        self.results = []
        self.rowcount = 0

    def execute(self, sql, params=()):
        s = " ".join(sql.strip().split())
        sl = s.lower()
        self.results = []
        self.rowcount = 0

        if sl.startswith(("select pg_advisory", "create ", "alter ", "drop ", "update blocked_ips", "update sensor_status", "update ai_explanations")):
            return
        if "select id, username, email from users order by id asc limit 1" in sl:
            u = DB.users[10]
            self.results = [dict(u)]
            return
        if "select email from users where id=%s limit 1" in sl:
            uid = int(params[0])
            if uid in DB.users:
                self.results = [{"email": DB.users[uid]["email"]}]
            return
        if sl.startswith("select last_seen from sensor_status"):
            return
        if sl.startswith("select id from sensors where owner_user_id=%s"):
            uid = params[0]
            for r in DB.sensors:
                if r["owner_user_id"] == uid:
                    self.results = [{"id": r["id"]}]
                    return
            return
        if sl.startswith("select * from sensors where owner_user_id=%s"):
            uid = params[0]
            for r in DB.sensors:
                if r["owner_user_id"] == uid:
                    self.results = [dict(r)]
                    return
            return
        if sl.startswith("insert into sensors("):
            uid = params[0]
            for r in DB.sensors:
                if r["owner_user_id"] == uid:
                    return
            if len(params) == 5:
                uid, kh, kp, created_at, last_seen_at = params
            else:
                uid, kh, kp, created_at = params
                last_seen_at = None
            sid = DB.next_sensor_id
            DB.next_sensor_id += 1
            row = {
                "id": sid,
                "owner_user_id": uid,
                "name": "My sensor",
                "key_hash": kh,
                "key_prefix": kp,
                "created_at": created_at,
                "last_seen_at": last_seen_at,
                "alert_email_level": "critical",
            }
            DB.sensors.append(row)
            self.results = [dict(row)]
            self.rowcount = 1
            return
        if sl.startswith("update sensors set key_hash=%s, key_prefix=%s where owner_user_id=%s"):
            kh, kp, uid = params
            for r in DB.sensors:
                if r["owner_user_id"] == uid:
                    r["key_hash"] = kh
                    r["key_prefix"] = kp
                    self.results = [dict(r)]
                    self.rowcount = 1
                    return
            return
        if sl.startswith("update sensors set name=%s, alert_email_level=%s where id=%s and owner_user_id=%s"):
            name, lv, sid, uid = params
            for r in DB.sensors:
                if r["id"] == sid and r["owner_user_id"] == uid:
                    r["name"] = name
                    r["alert_email_level"] = lv
                    self.results = [dict(r)]
                    self.rowcount = 1
                    return
            return
        if sl.startswith("select * from sensors where key_prefix=%s"):
            kp = params[0]
            self.results = [dict(r) for r in DB.sensors if r["key_prefix"] == kp]
            return
        if sl.startswith("select * from sensors where key_hash=%s"):
            kh = params[0]
            self.results = [dict(r) for r in DB.sensors if r["key_hash"] == kh]
            return
        if sl.startswith("update sensors set last_seen_at=%s where id=%s"):
            ts, sid = params
            for r in DB.sensors:
                if r["id"] == sid:
                    r["last_seen_at"] = ts
            return
        if sl.startswith("select * from sensor_status where owner_user_id=%s"):
            return
        if sl.startswith("update alerts set owner_user_id=%s"):
            return
        if sl.startswith("insert into alerts("):
            t, atype, src, dst, dport, detail, uid, sid = params
            aid = DB.next_alert_id
            DB.next_alert_id += 1
            row = {
                "id": aid,
                "time": t,
                "type": atype,
                "src": src,
                "dst": dst,
                "dport": dport,
                "detail": detail,
                "status": "new",
                "owner_user_id": uid,
                "sensor_id": sid,
            }
            DB.alerts.append(row)
            self.results = [{"id": aid}]
            self.rowcount = 1
            return
        if sl.startswith("select count(*) as n from alerts where owner_user_id"):
            uid = params[0]
            self.results = [{"n": sum(1 for a in DB.alerts if a["owner_user_id"] == uid)}]
            return
        if sl.startswith("select * from alerts where owner_user_id = %s order by id desc"):
            uid = params[0]
            self.results = [dict(a) for a in reversed(DB.alerts) if a["owner_user_id"] == uid]
            return
        if sl.startswith("select type, src from alerts where owner_user_id=%s"):
            uid = params[0]
            self.results = [{"type": a["type"], "src": a["src"]} for a in DB.alerts if a["owner_user_id"] == uid]
            return
        if sl.startswith("select * from email_throttle where bucket_key=%s"):
            bk = params[0]
            if bk in DB.email_throttle:
                self.results = [dict(DB.email_throttle[bk])]
            return
        if sl.startswith("insert into email_throttle("):
            bk, uid, cnt, supp, win_start, last_sent = params
            DB.email_throttle[bk] = {
                "bucket_key": bk,
                "owner_user_id": uid,
                "count": cnt,
                "suppressed_count": supp,
                "window_start": win_start,
                "last_sent": last_sent,
            }
            self.rowcount = 1
            return

    def fetchone(self):
        return self.results[0] if self.results else None

    def fetchall(self):
        return list(self.results)


class FakeConn:
    def cursor(self):
        return FakeCursor()
    def commit(self):
        pass
    def rollback(self):
        pass
    def close(self):
        pass


def _make_fake_psycopg2():
    fake_psycopg2 = types.ModuleType("psycopg2")
    fake_psycopg2.OperationalError = Exception
    fake_psycopg2.IntegrityError = Exception
    fake_psycopg2.connect = lambda dsn, **kw: FakeConn()
    fake_extras = types.ModuleType("psycopg2.extras")
    fake_extras.RealDictCursor = object
    fake_psycopg2.extras = fake_extras
    return fake_psycopg2, fake_extras


SENT_EMAILS = []


def _install_stubs(mp):
    mp.setenv("DATABASE_URL", "postgresql://test:test@localhost:5432/alerts_db")
    mp.setenv("AUTH_DATABASE_URL", "postgresql://test:test@localhost:5432/auth_db")
    mp.setenv("JWT_SECRET", "unit-test-secret-key-32-bytes-minimum")
    mp.setenv("SENSOR_KEY", "legacy-shared-pi-key-1234567890")
    mp.setenv("SMTP_USER", "sentineliq@example.com")
    mp.setenv("SMTP_APP_PASSWORD", "smtp-app-password")
    mp.setenv("FRONTEND_URL", "http://localhost:8088")
    mp.setitem(sys.modules, "jwt", _make_fake_jwt())
    mp.setitem(sys.modules, "flask", make_fake_flask(log_lines=LOG_LINES))
    fake_pg, fake_extras = _make_fake_psycopg2()
    mp.setitem(sys.modules, "psycopg2", fake_pg)
    mp.setitem(sys.modules, "psycopg2.extras", fake_extras)


@pytest.fixture()
def email_throttle_stubs(monkeypatch):
    global DB
    DB = PersistentDB()
    SENT_EMAILS.clear()
    LOG_LINES.clear()
    _install_stubs(monkeypatch)


def load_alert_service():
    spec = importlib.util.spec_from_file_location(
        "alert_app_email_throttle_unit", ROOT / "alert-service" / "app.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Capture emails synchronously for deterministic assertions
    mod.dispatch_mail = lambda to_email, subj, body, html_body=None: SENT_EMAILS.append(
        {"to": to_email, "subject": subj, "body": body, "html": html_body or ""}
    )
    return mod


def token_for(uid, username, role="viewer"):
    return _jwt_encode(
        {
            "sub": str(uid),
            "username": username,
            "role": role,
            "exp": datetime.now(timezone.utc) + timedelta(hours=2),
        },
        os.environ["JWT_SECRET"],
    )


def run_tests():
    mod = load_alert_service()
    client = mod.app.test_client()

    tok_a = token_for(10, "owner_a")
    tok_b = token_for(20, "owner_b")

    # Owner A already got the legacy sensor during init_db; regenerate A's key to get a fresh test key
    key_a = client.post("/sensors/me/regenerate", headers={"Authorization": f"Bearer {tok_a}"}).get_json()["key"]
    key_b = client.get("/sensors/me", headers={"Authorization": f"Bearer {tok_b}"}).get_json()["key"]

    # 1. Send 10 critical alerts from the same source IP (203.0.113.50) within 1 minute using Owner A's sensor key
    SENT_EMAILS.clear()
    LOG_LINES.clear()
    for i in range(10):
        r = client.post(
            "/ingest",
            headers={"X-Service-Key": key_a},
            json={"type": "DoS/SYN Flood", "src": "203.0.113.50", "dst": "192.0.2.5", "dport": "80", "detail": f"Burst #{i+1}"},
        )
        assert r.status_code == 201

    # Verify all 10 alerts are stored in DB, only 1 email was sent, and 9 are counted as suppressed
    a_alerts = client.get("/", headers={"Authorization": f"Bearer {tok_a}"}).get_json()
    assert a_alerts["total"] == 10, f"All 10 alerts must be stored, got {a_alerts['total']}"
    assert len(SENT_EMAILS) == 1, f"Expected 1 email for 10 rapid alerts from same source, got {len(SENT_EMAILS)}"
    assert SENT_EMAILS[0]["to"] == "owner_a@example.com"
    assert "request flood (denial of service) [DoS/SYN Flood]" in SENT_EMAILS[0]["subject"]
    assert "http://localhost:8088/alerts?alert=1" in SENT_EMAILS[0]["body"]
    assert 'href="http://localhost:8088/alerts?alert=1"' in SENT_EMAILS[0]["html"]
    assert "Open Alert #1 in Dashboard" in SENT_EMAILS[0]["html"]
    assert DB.email_throttle["pair:10:DoS/SYN Flood:203.0.113.50"]["suppressed_count"] == 9
    print("=== TEST 1: 10 critical alerts in 1 minute ===")
    for line in LOG_LINES:
        print("  [LOG]", line)
    print(f"  [PASS] 1 email sent to {SENT_EMAILS[0]['to']}, 9 suppressed in DB")

    # 2. Simulate 15 minutes later (adjust stored last_sent back by 901 seconds)
    DB.email_throttle["pair:10:DoS/SYN Flood:203.0.113.50"]["last_sent"] -= 901
    r11 = client.post(
        "/ingest",
        headers={"X-Service-Key": key_a},
        json={"type": "DoS/SYN Flood", "src": "203.0.113.50", "dst": "192.0.2.5", "dport": "80", "detail": "After 15m"},
    )
    assert r11.status_code == 201
    assert len(SENT_EMAILS) == 2
    assert "+9 more similar alerts" in SENT_EMAILS[1]["body"]
    assert DB.email_throttle["pair:10:DoS/SYN Flood:203.0.113.50"]["suppressed_count"] == 0
    print("=== TEST 2: 15 minutes later ===")
    print("  Subject:", SENT_EMAILS[1]["subject"])
    print("  Body excerpt:", [ln for ln in SENT_EMAILS[1]["body"].splitlines() if "more similar" in ln][0])
    print("  [PASS] Next email after 15m includes '+9 more similar alerts' and resets counter")

    # 3. Hit the hourly cap (3 individual emails per hour): we already sent 2 in this hour;
    #    send 3rd from a new source IP (.51) -> individual email #3;
    #    send 4th from a new source IP (.52) -> hits hourly cap (3/hr) and sends ONE summary email!
    client.post(
        "/ingest",
        headers={"X-Service-Key": key_a},
        json={"type": "DoS/SYN Flood", "src": "203.0.113.51", "dst": "192.0.2.5", "dport": "80"},
    )
    assert len(SENT_EMAILS) == 3  # 3rd individual email

    LOG_LINES.clear()
    client.post(
        "/ingest",
        headers={"X-Service-Key": key_a},
        json={"type": "DoS/SYN Flood", "src": "203.0.113.52", "dst": "192.0.2.5", "dport": "80"},
    )
    assert len(SENT_EMAILS) == 4  # 4th email is the 1/hour summary email
    sum_mail = SENT_EMAILS[3]
    assert "In the last hour: 13 alerts, 13 critical, top source IP 203.0.113.50" in sum_mail["body"]
    assert "http://localhost:8088/alerts" in sum_mail["body"]
    assert 'href="http://localhost:8088/alerts"' in sum_mail["html"]
    assert "Open Alerts Dashboard" in sum_mail["html"]

    # 5th distinct source in the same hour sends NO additional email (summary already sent this hour)
    client.post(
        "/ingest",
        headers={"X-Service-Key": key_a},
        json={"type": "DoS/SYN Flood", "src": "203.0.113.53", "dst": "192.0.2.5", "dport": "80"},
    )
    assert len(SENT_EMAILS) == 4
    print("=== TEST 3: Hourly cap (3/hour) + 1 summary email ===")
    print("  Summary body:", sum_mail["body"].splitlines()[0])
    print("  [PASS] Individual emails stopped at 3/hr and exactly 1 summary email was sent")

    # 4. With alert_email_level = 'off', no email is sent
    r_patch = client.patch(
        "/sensors/me",
        headers={"Authorization": f"Bearer {tok_b}"},
        json={"alert_email_level": "off"},
    )
    assert r_patch.status_code == 200 and r_patch.get_json()["alert_email_level"] == "off"
    before_n = len(SENT_EMAILS)
    client.post(
        "/ingest",
        headers={"X-Service-Key": key_b},
        json={"type": "DoS/SYN Flood", "src": "203.0.113.99", "dst": "192.0.2.9", "dport": "443"},
    )
    assert len(SENT_EMAILS) == before_n, "No email may be sent when alert_email_level == 'off'"
    print("=== TEST 4: alert_email_level = 'off' ===")
    print("  [PASS] Zero emails sent when alert_email_level is 'off'")

    # 5. Two owners: Owner B never receives an email for Owner A's alerts
    assert all(m["to"] == "owner_a@example.com" for m in SENT_EMAILS)
    print("=== TEST 5: Cross-owner email isolation ===")
    print("  [PASS] Owner B received 0 emails from Owner A's alerts")

    # 6. Restart the alert container (reload alert-service against the same DB): counters persist
    mod_restarted = load_alert_service()
    client2 = mod_restarted.app.test_client()
    before_restart_n = len(SENT_EMAILS)
    client2.post(
        "/ingest",
        headers={"X-Service-Key": key_a},
        json={"type": "DoS/SYN Flood", "src": "203.0.113.54", "dst": "192.0.2.5", "dport": "80"},
    )
    assert len(SENT_EMAILS) == before_restart_n, "Counters in email_throttle must persist across service restart"
    print("=== TEST 6: Service restart persistence ===")
    print("  [PASS] Throttle & hourly cap counters persisted in DB across service restart")


if __name__ == "__main__":
    with pytest.MonkeyPatch.context() as mp:
        _install_stubs(mp)
        run_tests()
