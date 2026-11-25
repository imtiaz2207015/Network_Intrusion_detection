"""
Automated verification of per-user sensor & data isolation (Tests 1-5)
across auth-service, alert-service, and analytics-service.
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


class FakeDBState:
    def __init__(self):
        self.users = [
            {
                "id": 1,
                "username": "legacy_owner",
                "email": "legacy@example.com",
                "password_hash": "",
                "role": "admin",
                "failed_attempts": 0,
                "locked_until": 0.0,
                "created_at": "2026-11-01 00:00:00",
            }
        ]
        self.sensors = []
        self.alerts = [
            {
                "id": 1,
                "time": "2026-11-17 08:00:00",
                "type": "PortScan",
                "src": "203.0.113.10",
                "dst": "192.0.2.5",
                "dport": "22",
                "detail": "Pre-existing legacy alert",
                "status": "new",
                "owner_user_id": None,
                "sensor_id": None,
            }
        ]
        self.sensor_status = [
            {
                "id": 1,
                "host": "rpi-legacy",
                "packets": 500,
                "uptime": 120,
                "last_seen": 1700000000.0,
                "owner_user_id": None,
                "sensor_id": None,
            }
        ]
        self.blocked_ips = []
        self.allowlist = []
        self.ai_explanations = []
        self.next_id = {"users": 2, "sensors": 1, "alerts": 2, "blocked_ips": 1}


STATE = FakeDBState()


class FakeCursor:
    def __init__(self, dsn):
        self.dsn = dsn
        self.results = []
        self.rowcount = 0

    def execute(self, sql, params=()):
        s = " ".join(sql.strip().split())
        sl = s.lower()
        self.results = []
        self.rowcount = 0

        if sl.startswith("select pg_advisory") or sl.startswith("create ") or sl.startswith("alter ") or sl.startswith("drop "):
            return

        # Legacy owner lookup in auth_db
        if "from users where lower(email)=lower(%s)" in sl and "select id, username, email" in sl:
            email = params[0].lower()
            for u in STATE.users:
                if u["email"].lower() == email:
                    self.results = [dict(u)]
                    return
            return
        if "select id, username, email from users order by id asc limit 1" in sl:
            if STATE.users:
                self.results = [dict(sorted(STATE.users, key=lambda x: x["id"])[0])]
            return

        # Legacy migration updates
        if sl.startswith("select last_seen from sensor_status where owner_user_id is null"):
            uid = params[0]
            for r in STATE.sensor_status:
                if r["owner_user_id"] is None or r["owner_user_id"] == uid:
                    self.results = [{"last_seen": r["last_seen"]}]
                    return
            return
        if sl.startswith("select id from sensors where owner_user_id=%s"):
            uid = params[0]
            for r in STATE.sensors:
                if r["owner_user_id"] == uid:
                    self.results = [{"id": r["id"]}]
                    return
            return
        if sl.startswith("select * from sensors where owner_user_id=%s"):
            uid = params[0]
            for r in STATE.sensors:
                if r["owner_user_id"] == uid:
                    self.results = [dict(r)]
                    return
            return
        if sl.startswith("insert into sensors("):
            uid = params[0]
            for r in STATE.sensors:
                if r["owner_user_id"] == uid:
                    return
            if len(params) == 5:
                uid, kh, kp, created_at, last_seen_at = params
                name = "My sensor"
            elif len(params) == 4:
                uid, kh, kp, created_at = params
                name, last_seen_at = "My sensor", None
            else:
                uid, name, kh, kp, created_at, last_seen_at = params
            sid = STATE.next_id["sensors"]
            STATE.next_id["sensors"] += 1
            row = {
                "id": sid,
                "owner_user_id": uid,
                "name": name,
                "key_hash": kh,
                "key_prefix": kp,
                "created_at": created_at,
                "last_seen_at": last_seen_at,
            }
            STATE.sensors.append(row)
            self.results = [dict(row)]
            self.rowcount = 1
            return
        if sl.startswith("update sensors set key_hash=%s, key_prefix=%s where owner_user_id=%s"):
            kh, kp, uid = params
            for r in STATE.sensors:
                if r["owner_user_id"] == uid:
                    r["key_hash"] = kh
                    r["key_prefix"] = kp
                    self.results = [dict(r)]
                    self.rowcount = 1
                    return
            return
        if sl.startswith("update sensors set name=%s where id=%s and owner_user_id=%s"):
            name, sid, uid = params
            for r in STATE.sensors:
                if r["id"] == sid and r["owner_user_id"] == uid:
                    r["name"] = name
                    self.results = [dict(r)]
                    self.rowcount = 1
                    return
            return
        if sl.startswith("update sensors set last_seen_at=%s where id=%s"):
            ts, sid = params
            for r in STATE.sensors:
                if r["id"] == sid:
                    r["last_seen_at"] = ts
                    self.rowcount = 1
            return
        if sl.startswith("select * from sensors where key_prefix=%s"):
            kp = params[0]
            self.results = [dict(r) for r in STATE.sensors if r["key_prefix"] == kp]
            return
        if sl.startswith("select * from sensors where key_hash=%s"):
            kh = params[0]
            self.results = [dict(r) for r in STATE.sensors if r["key_hash"] == kh]
            return

        if sl.startswith("update alerts set owner_user_id=%s, sensor_id=coalesce(sensor_id, %s) where owner_user_id is null"):
            uid, sid = params
            for a in STATE.alerts:
                if a["owner_user_id"] is None:
                    a["owner_user_id"] = uid
                    a["sensor_id"] = a["sensor_id"] or sid
                    self.rowcount += 1
            return
        if sl.startswith("update blocked_ips set owner_user_id=%s"):
            uid, sid = params
            for b in STATE.blocked_ips:
                if b["owner_user_id"] is None:
                    b["owner_user_id"] = uid
                    b["sensor_id"] = b["sensor_id"] or sid
            return
        if sl.startswith("update sensor_status set id=%s, owner_user_id=%s"):
            uid, _, sid = params
            for st in STATE.sensor_status:
                if st["owner_user_id"] is None:
                    st["id"] = uid
                    st["owner_user_id"] = uid
                    st["sensor_id"] = st["sensor_id"] or sid
            return
        if sl.startswith("update ai_explanations set owner_user_id=%s"):
            return

        # Alerts insert & queries
        if sl.startswith("insert into alerts("):
            t, atype, src, dst, dport, detail, uid, sid = params
            aid = STATE.next_id["alerts"]
            STATE.next_id["alerts"] += 1
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
            STATE.alerts.append(row)
            self.results = [{"id": aid}]
            self.rowcount = 1
            return
        if sl.startswith("select count(*) as n from alerts where owner_user_id"):
            uid = params[0]
            rows = [a for a in STATE.alerts if a["owner_user_id"] == uid]
            self.results = [{"n": len(rows)}]
            return
        if sl.startswith("select * from alerts where owner_user_id = %s order by id desc"):
            uid = params[0]
            rows = [dict(a) for a in sorted(STATE.alerts, key=lambda x: x["id"], reverse=True) if a["owner_user_id"] == uid]
            self.results = rows
            return
        if "from alerts where id=%s and owner_user_id=%s" in sl and sl.startswith("select"):
            aid, uid = params
            for a in STATE.alerts:
                if a["id"] == aid and a["owner_user_id"] == uid:
                    self.results = [dict(a)]
                    return
            return
        if sl.startswith("update alerts set status=%s where id=%s and owner_user_id=%s"):
            st, aid, uid = params
            for a in STATE.alerts:
                if a["id"] == aid and a["owner_user_id"] == uid:
                    a["status"] = st
                    self.rowcount = 1
                    return
            return
        if "select type, count(*) as n from alerts where owner_user_id" in sl:
            uid = params[0]
            counts = {}
            for a in STATE.alerts:
                if a["owner_user_id"] == uid:
                    counts[a["type"]] = counts.get(a["type"], 0) + 1
            self.results = [{"type": k, "n": v} for k, v in counts.items()]
            return
        if "select src, count(*) as n from alerts where owner_user_id" in sl:
            uid = params[0]
            counts = {}
            for a in STATE.alerts:
                if a["owner_user_id"] == uid:
                    counts[a["src"]] = counts.get(a["src"], 0) + 1
            self.results = [{"src": k, "n": v} for k, v in counts.items()]
            return
        if "select dport, count(*) as n from alerts where owner_user_id" in sl:
            uid = params[0]
            self.results = []
            return
        if "select dst, count(*) as n from alerts where owner_user_id" in sl:
            uid = params[0]
            self.results = []
            return
        if "select count(distinct src) as s" in sl:
            uid = params[0]
            srcs = {a["src"] for a in STATE.alerts if a["owner_user_id"] == uid}
            dsts = {a["dst"] for a in STATE.alerts if a["owner_user_id"] == uid and a["dst"] not in ("-", "")}
            self.results = [{"s": len(srcs), "t": len(dsts)}]
            return
        if "select substring(time,1,%s) as h" in sl:
            blen, uid, _ = params
            buckets = {}
            for a in STATE.alerts:
                if a["owner_user_id"] == uid:
                    h = a["time"][:blen]
                    buckets[h] = buckets.get(h, 0) + 1
            self.results = [{"h": k, "n": v} for k, v in sorted(buckets.items())]
            return
        if "select time, type, src, dst, dport from alerts where owner_user_id" in sl:
            uid = params[0]
            self.results = [dict(a) for a in STATE.alerts if a["owner_user_id"] == uid]
            return

        # Sensor status
        if sl.startswith("select * from sensor_status where owner_user_id=%s"):
            uid = params[0]
            for r in STATE.sensor_status:
                if r["owner_user_id"] == uid:
                    self.results = [dict(r)]
                    return
            return

        # Blocked IPs
        if sl.startswith("update blocked_ips set status='expired'"):
            return
        if sl.startswith("select 1 from allowlist where owner_user_id=%s and ip=%s"):
            return
        if sl.startswith("select ip from allowlist where owner_user_id=%s"):
            return
        if sl.startswith("select count(*) as n from blocked_ips where owner_user_id=%s"):
            uid = params[0]
            n = sum(1 for b in STATE.blocked_ips if b["owner_user_id"] == uid and b["status"] in ("active", "unblock_requested"))
            self.results = [{"n": n}]
            return
        if sl.startswith("insert into blocked_ips("):
            ip, alert_id, blocked_by, blocked_at, expires_at, uid, sid = params
            for b in STATE.blocked_ips:
                if b["owner_user_id"] == uid and b["ip"] == ip and b["status"] in ("active", "unblock_requested"):
                    import psycopg2
                    raise psycopg2.IntegrityError("duplicate block")
            bid = STATE.next_id["blocked_ips"]
            STATE.next_id["blocked_ips"] += 1
            row = {
                "id": bid,
                "ip": ip,
                "alert_id": alert_id,
                "status": "active",
                "blocked_by": blocked_by,
                "blocked_at": blocked_at,
                "expires_at": expires_at,
                "owner_user_id": uid,
                "sensor_id": sid,
                "resolved_by": None,
                "resolved_at": None,
            }
            STATE.blocked_ips.append(row)
            self.results = [dict(row)]
            self.rowcount = 1
            return
        if sl.startswith("select * from blocked_ips where owner_user_id=%s"):
            uid = params[0]
            self.results = [dict(b) for b in sorted(STATE.blocked_ips, key=lambda x: x["id"], reverse=True) if b["owner_user_id"] == uid]
            return
        if sl.startswith("select ip from blocked_ips where owner_user_id=%s"):
            uid = params[0]
            self.results = [{"ip": b["ip"]} for b in STATE.blocked_ips if b["owner_user_id"] == uid and b["status"] in ("active", "unblock_requested")]
            return
        if sl.startswith("update blocked_ips set status='unblocked'"):
            resolved_by, resolved_at, bid, uid = params
            for b in STATE.blocked_ips:
                if b["id"] == bid and b["owner_user_id"] == uid and b["status"] in ("active", "unblock_requested"):
                    b["status"] = "unblocked"
                    b["resolved_by"] = resolved_by
                    b["resolved_at"] = resolved_at
                    self.rowcount = 1
                    return
            return

    def fetchone(self):
        return self.results[0] if self.results else None

    def fetchall(self):
        return list(self.results)

    def __iter__(self):
        return iter(self.results)


class FakeConn:
    def __init__(self, dsn):
        self.dsn = dsn

    def cursor(self):
        return FakeCursor(self.dsn)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def _install_stubs(mp):
    mp.setenv("DATABASE_URL", "postgresql://test:test@localhost:5432/alerts_db")
    mp.setenv("AUTH_DATABASE_URL", "postgresql://test:test@localhost:5432/auth_db")
    mp.setenv("JWT_SECRET", "unit-test-secret-key-32-bytes-minimum")
    mp.setenv("SENSOR_KEY", "legacy-shared-pi-key-1234567890")
    mp.setenv("LEGACY_OWNER_EMAIL", "legacy@example.com")

    fake_jwt = types.ModuleType("jwt")
    fake_jwt.PyJWTError = PyJWTError
    fake_jwt.encode = _jwt_encode
    fake_jwt.decode = _jwt_decode
    mp.setitem(sys.modules, "jwt", fake_jwt)

    mp.setitem(sys.modules, "flask", make_fake_flask())

    fake_psycopg2 = types.ModuleType("psycopg2")
    fake_psycopg2.OperationalError = Exception
    fake_psycopg2.IntegrityError = Exception
    fake_psycopg2.connect = lambda dsn, **kw: FakeConn(dsn)
    fake_extras = types.ModuleType("psycopg2.extras")
    fake_extras.RealDictCursor = object
    fake_psycopg2.extras = fake_extras
    mp.setitem(sys.modules, "psycopg2", fake_psycopg2)
    mp.setitem(sys.modules, "psycopg2.extras", fake_extras)

    # Stub reportlab if not installed in host Python
    for mod_name in (
        "reportlab",
        "reportlab.lib",
        "reportlab.lib.colors",
        "reportlab.lib.pagesizes",
        "reportlab.lib.styles",
        "reportlab.lib.units",
        "reportlab.platypus",
        "reportlab.graphics",
        "reportlab.graphics.shapes",
        "reportlab.graphics.charts",
        "reportlab.graphics.charts.barcharts",
    ):
        if mod_name not in sys.modules:
            m = types.ModuleType(mod_name)
            m.A4 = (595, 842)
            m.cm = 28.35
            m.HexColor = lambda x: x
            m.white = "#fff"
            m.grey = "#888"
            m.getSampleStyleSheet = lambda: {"Title": None, "Normal": None, "Heading2": None}
            m.SimpleDocTemplate = object
            m.Paragraph = object
            m.Spacer = object
            m.Table = object
            m.TableStyle = object
            m.Drawing = object
            m.VerticalBarChart = object
            mp.setitem(sys.modules, mod_name, m)
    mp.setattr(sys.modules["reportlab.lib"], "colors", sys.modules["reportlab.lib.colors"], raising=False)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def isolation_apps(monkeypatch):
    global STATE
    STATE = FakeDBState()
    _install_stubs(monkeypatch)
    alert_mod = load_module("alert_app_isolation_unit", "alert-service/app.py")
    analytics_mod = load_module("analytics_app_isolation_unit", "analytics-service/app.py")
    return alert_mod, analytics_mod


def token_for(uid, username, role="viewer"):
    return _jwt_encode(
        {
            "sub": str(uid),
            "username": username,
            "role": role,
            "exp": datetime.now(timezone.utc) + timedelta(hours=2),
        },
        os.environ["JWT_SECRET"],
        algorithm="HS256",
    )


def run_tests(alert_mod, analytics_mod):
    alert_client = alert_mod.app.test_client()
    analytics_client = analytics_mod.app.test_client()

    tok_legacy = token_for(1, "legacy_owner", "admin")
    tok_a = token_for(10, "user_a", "viewer")
    tok_b = token_for(20, "user_b", "viewer")
    tok_c = token_for(30, "user_c", "viewer")

    # Test 3: Verify legacy migration assigned alert #1 and legacy SENSOR_KEY to user 1
    assert STATE.alerts[0]["owner_user_id"] == 1, "Legacy alert must be assigned to legacy_owner (id=1)"
    r_leg_ing = alert_client.post(
        "/ingest",
        headers={"X-Service-Key": "legacy-shared-pi-key-1234567890"},
        json={"type": "PortScan", "src": "203.0.113.11", "dst": "192.0.2.5", "dport": "80"},
    )
    assert r_leg_ing.status_code == 201, f"Legacy key must work: {r_leg_ing.status_code}"
    r_leg_list = alert_client.get("/", headers={"Authorization": f"Bearer {tok_legacy}"}).get_json()
    assert r_leg_list["total"] == 2, f"Legacy owner should see 2 alerts, got {r_leg_list['total']}"
    print("[PASS] Test 3: Legacy migration & legacy SENSOR_KEY work under legacy_owner (id=1)")

    # Test 1: User A creates sensor lazily (key returned once), posts alert; User B sees 0 everywhere
    r_sa1 = alert_client.get("/sensors/me", headers={"Authorization": f"Bearer {tok_a}"}).get_json()
    assert "key" in r_sa1 and len(r_sa1["key"]) >= 32, "First GET /sensors/me must return full key"
    key_a = r_sa1["key"]
    r_sa2 = alert_client.get("/sensors/me", headers={"Authorization": f"Bearer {tok_a}"}).get_json()
    assert "key" not in r_sa2, "Second GET /sensors/me must NOT return full key"

    r_ing_a = alert_client.post(
        "/ingest",
        headers={"X-Service-Key": key_a},
        json={"type": "DoS/SYN Flood", "src": "203.0.113.77", "dst": "192.0.2.10", "dport": "443", "detail": "A only"},
    )
    assert r_ing_a.status_code == 201
    aid_a = r_ing_a.get_json()["id"]

    a_list = alert_client.get("/", headers={"Authorization": f"Bearer {tok_a}"}).get_json()
    b_list = alert_client.get("/", headers={"Authorization": f"Bearer {tok_b}"}).get_json()
    b_stats = alert_client.get("/stats", headers={"Authorization": f"Bearer {tok_b}"}).get_json()
    b_sum = analytics_client.get("/summary?hours=24", headers={"Authorization": f"Bearer {tok_b}"}).get_json()
    b_blk = alert_client.get("/blocked-ips", headers={"Authorization": f"Bearer {tok_b}"}).get_json()

    assert a_list["total"] == 1 and a_list["alerts"][0]["id"] == aid_a
    assert b_list["total"] == 0 and b_list["alerts"] == []
    assert b_stats["total"] == 0 and b_stats["counts"] == {}
    assert b_sum["total"] == 0 and b_sum["timeline"] == []
    assert b_blk["blocked"] == []
    print("[PASS] Test 1: User A sees only A's alert; User B sees 0 across alerts, stats, analytics, blocked IPs")

    # User A blocks 203.0.113.77
    r_blk_a = alert_client.post(
        "/block-ip",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={"ip": "203.0.113.77", "alert_id": aid_a, "minutes": 10},
    )
    assert r_blk_a.status_code == 201
    bid_a = r_blk_a.get_json()["id"]

    # Test 2: User B attempts GET/PATCH/POST on A's alert id, blocking A's alert, unblocking A's block -> all 404
    assert alert_client.get(f"/{aid_a}", headers={"Authorization": f"Bearer {tok_b}"}).status_code == 404
    assert alert_client.patch(f"/{aid_a}", headers={"Authorization": f"Bearer {tok_b}"}, json={"status": "resolved"}).status_code == 404
    assert alert_client.patch(f"/{aid_a}/status", headers={"Authorization": f"Bearer {tok_b}"}, json={"status": "resolved"}).status_code == 404
    assert alert_client.post(f"/{aid_a}/explain", headers={"Authorization": f"Bearer {tok_b}"}).status_code == 404
    assert alert_client.post("/block-ip", headers={"Authorization": f"Bearer {tok_b}"}, json={"ip": "203.0.113.77", "alert_id": aid_a}).status_code == 404
    assert alert_client.post(f"/blocked-ips/{bid_a}/unblock", headers={"Authorization": f"Bearer {tok_b}"}).status_code == 404
    print("[PASS] Test 2: User B gets 404 on GET/PATCH/POST A's alert, block A's alert, and unblock A's block")

    # Test 4: Regenerate A's key -> old key returns 401, new key returns 201
    r_regen = alert_client.post("/sensors/me/regenerate", headers={"Authorization": f"Bearer {tok_a}"}).get_json()
    new_key_a = r_regen["key"]
    assert new_key_a != key_a
    assert alert_client.post("/ingest", headers={"X-Service-Key": key_a}, json={"type": "PortScan", "src": "203.0.113.88"}).status_code == 401
    assert alert_client.post("/ingest", headers={"X-Service-Key": new_key_a}, json={"type": "PortScan", "src": "203.0.113.88"}).status_code == 201
    print("[PASS] Test 4: After regenerating A's key, old key returns 401 and new key returns 201")

    # Test 5: Brand-new User C gets empty data & sensor offline across all endpoints
    c_sensor = alert_client.get("/sensor", headers={"Authorization": f"Bearer {tok_c}"}).get_json()
    c_alerts = alert_client.get("/", headers={"Authorization": f"Bearer {tok_c}"}).get_json()
    c_stats = alert_client.get("/stats", headers={"Authorization": f"Bearer {tok_c}"}).get_json()
    c_blocks = alert_client.get("/blocked-ips", headers={"Authorization": f"Bearer {tok_c}"}).get_json()
    c_summary = analytics_client.get("/summary?hours=24", headers={"Authorization": f"Bearer {tok_c}"}).get_json()
    assert c_sensor == {"online": False, "seen": False}
    assert c_alerts == {"alerts": [], "total": 0}
    assert c_stats == {"counts": {}, "sources": [], "total": 0}
    assert c_blocks == {"blocked": []}
    assert c_summary["total"] == 0
    print("[PASS] Test 5: Brand-new User C gets empty lists, zeros, and sensor offline with no errors")


if __name__ == "__main__":
    with pytest.MonkeyPatch.context() as mp:
        _install_stubs(mp)
        run_tests(
            load_module("alert_app_isolation_unit", "alert-service/app.py"),
            load_module("analytics_app_isolation_unit", "analytics-service/app.py"),
        )
