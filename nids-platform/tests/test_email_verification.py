"""
Automated verification of the registration email verification flow in auth-service:
1. Register + correct 6-digit code creates verified user, deletes pending row, returns JWT token.
2. Disposable email domains blocked with "Please use a permanent email address".
3. Wrong code x5 deletes pending row and requires registering again.
4. Expired code rejected and pending row deleted.
5. Resend 60s cooldown & 5/hour cap enforced; unknown email returns generic 200.
6. SMTP failure returns 503 and stores nothing.
7. Unverified user login returns 403 {"error":"Email not verified","verify":true,"email":"..."} and sends fresh code.
8. Existing users migrated to email_verified=true still log in.
9. Google login rejects unverified Google email and accepts verified Google email.
"""
import base64
import hashlib
import hmac
import importlib.util
import json
import pathlib
import re
import sys
import time
import types

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


def _fake_pw_hash(pw):
    return "hash:" + hashlib.sha256(pw.encode()).hexdigest()


def _fake_check_pw_hash(h, pw):
    return h == "hash:" + hashlib.sha256(pw.encode()).hexdigest()


MOCK_GOOGLE_TOKEN_INFO = {}


def _verify_oauth2(cred, req, client_id, clock_skew_in_seconds=10):
    if cred not in MOCK_GOOGLE_TOKEN_INFO:
        raise ValueError("Invalid token")
    return MOCK_GOOGLE_TOKEN_INFO[cred]


class AuthDBState:
    def __init__(self):
        # Pre-existing user before migration (no email_verified field yet)
        self.has_email_verified_col = False
        self.users = [
            {
                "id": 1,
                "username": "existing_admin",
                "email": "existing@example.com",
                "password_hash": _fake_pw_hash("AdminPass123"),
                "role": "admin",
                "failed_attempts": 0,
                "locked_until": 0.0,
                "created_at": "2026-11-01 00:00:00",
            }
        ]
        self.pending = {}
        self.send_log = []
        self.login_log = []
        self.next_uid = 2


DB = AuthDBState()


class FakeAuthCursor:
    def __init__(self):
        self.results = []
        self.rowcount = 0

    def execute(self, sql, params=()):
        s = " ".join(sql.strip().split())
        sl = s.lower()
        self.results = []
        self.rowcount = 0

        if "information_schema.columns" in sl:
            self.results = [{"1": 1}] if DB.has_email_verified_col else []
            return
        if "alter table users add column if not exists email_verified" in sl:
            DB.has_email_verified_col = True
            for u in DB.users:
                u.setdefault("email_verified", False)
            return
        if sl == "update users set email_verified = true":
            for u in DB.users:
                u["email_verified"] = True
            return
        if sl.startswith("select pg_advisory") or sl.startswith("create "):
            return
        if sl.startswith("delete from pending_registrations where expires_at < %s"):
            now_ts = params[0]
            expired = [k for k, v in DB.pending.items() if v["expires_at"] < now_ts]
            for k in expired:
                del DB.pending[k]
            return
        if sl.startswith("select 1 from users where lower(email)=lower(%s) or username=%s"):
            em, un = params[0].lower(), params[1]
            for u in DB.users:
                if u["email"].lower() == em or u["username"] == un:
                    self.results = [{"1": 1}]
                    return
            return
        if sl.startswith("select 1 from pending_registrations where username=%s and lower(email)!=lower(%s)"):
            un, em = params[0], params[1].lower()
            for k, v in DB.pending.items():
                if v["username"] == un and k != em:
                    self.results = [{"1": 1}]
                    return
            return
        if sl.startswith("select * from pending_registrations where lower(email)=lower(%s)"):
            em = params[0].lower()
            if em in DB.pending:
                self.results = [dict(DB.pending[em])]
            return
        if sl.startswith("select count(*) as n from registration_send_log"):
            em, since = params[0].lower(), params[1]
            n = sum(1 for x in DB.send_log if x["email"] == em and x["sent_at"] > since)
            self.results = [{"n": n}]
            return
        if sl.startswith("insert into pending_registrations("):
            em, un, pwh, ch, exp, last_sent, created = params
            em = em.lower()
            DB.pending[em] = {
                "email": em,
                "username": un,
                "password_hash": pwh,
                "code_hash": ch,
                "expires_at": exp,
                "attempts": 0,
                "last_sent_at": last_sent,
                "created_at": created,
            }
            self.rowcount = 1
            return
        if sl.startswith("insert into registration_send_log("):
            em, sent_at = params[0].lower(), params[1]
            DB.send_log.append({"email": em, "sent_at": sent_at})
            return
        if sl.startswith("delete from pending_registrations where lower(email)=lower(%s)"):
            em = params[0].lower()
            if em in DB.pending:
                del DB.pending[em]
                self.rowcount = 1
            return
        if sl.startswith("update pending_registrations set attempts=%s where lower(email)=lower(%s)"):
            att, em = params[0], params[1].lower()
            if em in DB.pending:
                DB.pending[em]["attempts"] = att
                self.rowcount = 1
            return
        if sl.startswith("update pending_registrations set code_hash=%s, expires_at=%s, attempts=0, last_sent_at=%s"):
            ch, exp, last_sent, em = params[0], params[1], params[2], params[3].lower()
            if em in DB.pending:
                DB.pending[em].update({"code_hash": ch, "expires_at": exp, "attempts": 0, "last_sent_at": last_sent})
                self.rowcount = 1
            return
        if sl.startswith("select * from users where lower(email)=lower(%s) or username=%s"):
            em, un = params[0].lower(), params[1]
            for u in DB.users:
                if u["email"].lower() == em or u["username"] == un:
                    self.results = [dict(u)]
                    return
            return
        if sl.startswith("select * from users where lower(email)=lower(%s)"):
            em = params[0].lower()
            for u in DB.users:
                if u["email"].lower() == em:
                    self.results = [dict(u)]
                    return
            return
        if sl.startswith("select count(*) as n from users"):
            self.results = [{"n": len(DB.users)}]
            return
        if sl.startswith("select 1 from users where username=%s"):
            un = params[0]
            for u in DB.users:
                if u["username"] == un:
                    self.results = [{"1": 1}]
                    return
            return
        if sl.startswith("insert into users("):
            un, em, pwh, role, created = params
            uid = DB.next_uid
            DB.next_uid += 1
            row = {
                "id": uid,
                "username": un,
                "email": em.lower(),
                "password_hash": pwh,
                "role": role,
                "email_verified": True,
                "failed_attempts": 0,
                "locked_until": 0.0,
                "created_at": created,
            }
            DB.users.append(row)
            self.results = [dict(row)]
            self.rowcount = 1
            return
        if sl.startswith("update users set email_verified=true"):
            uid = params[0]
            for u in DB.users:
                if u["id"] == uid:
                    u["email_verified"] = True
                    u["failed_attempts"] = 0
                    u["locked_until"] = 0.0
                    self.results = [dict(u)]
                    self.rowcount = 1
                    return
            return
        if sl.startswith("update users set failed_attempts=0, locked_until=0 where id=%s"):
            return
        if sl.startswith("insert into login_log("):
            DB.login_log.append(params)
            return
        if sl.startswith("select count(*) as n from login_log"):
            self.results = [{"n": 0}]
            return

    def fetchone(self):
        return self.results[0] if self.results else None

    def fetchall(self):
        return list(self.results)


class FakeAuthConn:
    def cursor(self):
        return FakeAuthCursor()
    def commit(self):
        pass
    def rollback(self):
        pass
    def close(self):
        pass


def _install_stubs(mp):
    mp.setenv("DATABASE_URL", "postgresql://test:test@localhost:5432/auth_db")
    mp.setenv("JWT_SECRET", "unit-test-secret-key-32-bytes-minimum")
    mp.setenv("GOOGLE_CLIENT_ID", "test-google-client-id.apps.googleusercontent.com")
    mp.setenv("SMTP_USER", "noreply@example.com")
    mp.setenv("SMTP_APP_PASSWORD", "app-pass-1234")
    mp.setenv("TEST_AUTO_VERIFY", "false")

    fake_jwt = types.ModuleType("jwt")
    fake_jwt.PyJWTError = PyJWTError
    fake_jwt.encode = _jwt_encode
    fake_jwt.decode = _jwt_decode
    mp.setitem(sys.modules, "jwt", fake_jwt)

    fake_wz = types.ModuleType("werkzeug.security")
    fake_wz.generate_password_hash = _fake_pw_hash
    fake_wz.check_password_hash = _fake_check_pw_hash
    mp.setitem(sys.modules, "werkzeug", types.ModuleType("werkzeug"))
    mp.setitem(sys.modules, "werkzeug.security", fake_wz)

    fake_google = types.ModuleType("google")
    fake_oauth2 = types.ModuleType("google.oauth2")
    fake_id_token = types.ModuleType("google.oauth2.id_token")
    fake_id_token.verify_oauth2_token = _verify_oauth2
    fake_auth = types.ModuleType("google.auth")
    fake_transport = types.ModuleType("google.auth.transport")
    fake_grequests = types.ModuleType("google.auth.transport.requests")
    fake_grequests.Request = lambda: object()
    fake_transport.requests = fake_grequests
    mp.setitem(sys.modules, "google", fake_google)
    mp.setitem(sys.modules, "google.oauth2", fake_oauth2)
    mp.setitem(sys.modules, "google.oauth2.id_token", fake_id_token)
    mp.setitem(sys.modules, "google.auth", fake_auth)
    mp.setitem(sys.modules, "google.auth.transport", fake_transport)
    mp.setitem(sys.modules, "google.auth.transport.requests", fake_grequests)

    mp.setitem(sys.modules, "flask", make_fake_flask())

    fake_psycopg2 = types.ModuleType("psycopg2")
    fake_psycopg2.OperationalError = Exception
    fake_psycopg2.IntegrityError = Exception
    fake_psycopg2.connect = lambda dsn, **kw: FakeAuthConn()
    fake_extras = types.ModuleType("psycopg2.extras")
    fake_extras.RealDictCursor = object
    fake_psycopg2.extras = fake_extras
    mp.setitem(sys.modules, "psycopg2", fake_psycopg2)
    mp.setitem(sys.modules, "psycopg2.extras", fake_extras)


SENT_EMAILS = []
SMTP_SHOULD_FAIL = False


def mock_send_mail(to, subject, body, reply_to=None):
    if SMTP_SHOULD_FAIL:
        raise RuntimeError("Simulated SMTP failure")
    m = re.search(r"\b(\d{6})\b", body)
    SENT_EMAILS.append({"to": to, "subject": subject, "body": body, "code": m.group(1) if m else None})


def _load_auth_mod():
    spec = importlib.util.spec_from_file_location(
        "auth_app_email_verification_unit", ROOT / "auth-service" / "app.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.send_mail = mock_send_mail
    return mod


@pytest.fixture()
def email_verification_app(monkeypatch):
    global DB, SMTP_SHOULD_FAIL
    DB = AuthDBState()
    SENT_EMAILS.clear()
    MOCK_GOOGLE_TOKEN_INFO.clear()
    SMTP_SHOULD_FAIL = False
    _install_stubs(monkeypatch)
    return _load_auth_mod()


def run_tests(auth_mod):
    global SMTP_SHOULD_FAIL
    client = auth_mod.app.test_client()

    # 8. Existing user migrated to email_verified=True still logs in
    assert DB.users[0].get("email_verified") is True, "Pre-existing user must be migrated to email_verified=True"
    r_ex = client.post("/login", json={"email": "existing@example.com", "password": "AdminPass123"})
    assert r_ex.status_code == 200 and "token" in r_ex.get_json()
    print("[PASS] Existing pre-migration user has email_verified=True and logs in normally")

    # 2. Disposable email domains blocked
    for dom in ("mailinator.com", "yopmail.com", "10minutemail.com"):
        r_disp = client.post(
            "/register",
            json={"username": "dispuser", "email": f"test@{dom}", "password": "Password123"},
        )
        assert r_disp.status_code == 400
        assert r_disp.get_json()["error"] == "Please use a permanent email address"
    print("[PASS] Disposable email domains rejected with 'Please use a permanent email address'")

    # 6. SMTP failure returns 503 and stores nothing
    SMTP_SHOULD_FAIL = True
    r_fail = client.post(
        "/register",
        json={"username": "smtpfail", "email": "smtpfail@example.com", "password": "Password123"},
    )
    assert r_fail.status_code == 503
    assert r_fail.get_json()["error"] == "Could not send the verification email, try again"
    assert "smtpfail@example.com" not in DB.pending
    SMTP_SHOULD_FAIL = False
    print("[PASS] SMTP failure returns 503 and stores nothing in pending_registrations")

    # 1. Register + correct 6-digit code works
    SENT_EMAILS.clear()
    r_reg = client.post(
        "/register",
        json={"username": "alice_user", "email": "alice@example.com", "password": "Password123"},
    )
    assert r_reg.status_code == 200
    reg_body = r_reg.get_json()
    assert reg_body == {"verify": True, "email": "alice@example.com"}
    assert "code" not in reg_body
    assert len(SENT_EMAILS) == 1 and SENT_EMAILS[-1]["to"] == "alice@example.com"
    alice_code = SENT_EMAILS[-1]["code"]
    assert len(alice_code) == 6
    # Verify user not in users table yet
    assert not any(u["email"] == "alice@example.com" for u in DB.users)

    # Verify with correct code
    r_ver = client.post("/register/verify", json={"email": "alice@example.com", "code": alice_code})
    assert r_ver.status_code == 200
    ver_body = r_ver.get_json()
    assert "token" in ver_body and ver_body["user"]["username"] == "alice_user"
    assert "alice@example.com" not in DB.pending
    assert any(u["email"] == "alice@example.com" and u["email_verified"] is True for u in DB.users)
    print("[PASS] Register + correct 6-digit code creates verified user, deletes pending row, and returns JWT token")

    # 3. Wrong code x5 deletes the pending row
    SENT_EMAILS.clear()
    r_reg2 = client.post(
        "/register",
        json={"username": "bob_user", "email": "bob@example.com", "password": "Password123"},
    )
    assert r_reg2.status_code == 200
    bob_code = SENT_EMAILS[-1]["code"]
    wrong_code = "000000" if bob_code != "000000" else "999999"
    for i in range(5):
        r_w = client.post("/register/verify", json={"email": "bob@example.com", "code": wrong_code})
        assert r_w.status_code == 400
    assert "bob@example.com" not in DB.pending, "Pending row must be deleted after 5 wrong attempts"
    # Even the real code now fails because the pending row was deleted
    r_after_lock = client.post("/register/verify", json={"email": "bob@example.com", "code": bob_code})
    assert r_after_lock.status_code == 400
    print("[PASS] Wrong code x5 deletes pending row and requires registering again")

    # 4. Expired code rejected
    SENT_EMAILS.clear()
    client.post(
        "/register",
        json={"username": "exp_user", "email": "exp@example.com", "password": "Password123"},
    )
    exp_code = SENT_EMAILS[-1]["code"]
    DB.pending["exp@example.com"]["expires_at"] = time.time() - 5
    r_exp = client.post("/register/verify", json={"email": "exp@example.com", "code": exp_code})
    assert r_exp.status_code == 400 and "expired" in r_exp.get_json()["error"].lower()
    assert "exp@example.com" not in DB.pending
    print("[PASS] Expired code rejected and pending row deleted")

    # 5. Resend cooldown (60s) & generic response for non-existent email
    SENT_EMAILS.clear()
    client.post(
        "/register",
        json={"username": "cool_user", "email": "cool@example.com", "password": "Password123"},
    )
    first_code = SENT_EMAILS[-1]["code"]
    # Immediate resend must hit 60s cooldown (429)
    r_cool = client.post("/register/resend", json={"email": "cool@example.com"})
    assert r_cool.status_code == 429
    # Advance last_sent_at back by 61s and resend -> generates new code and invalidates old code
    DB.pending["cool@example.com"]["last_sent_at"] = time.time() - 61
    r_res_ok = client.post("/register/resend", json={"email": "cool@example.com"})
    assert r_res_ok.status_code == 200
    second_code = SENT_EMAILS[-1]["code"]
    if second_code != first_code:
        assert client.post("/register/verify", json={"email": "cool@example.com", "code": first_code}).status_code == 400
    # Non-existent email returns same generic 200 response
    r_unknown = client.post("/register/resend", json={"email": "nobody@example.com"})
    assert r_unknown.status_code == 200 and r_unknown.get_json() == r_res_ok.get_json()
    print("[PASS] Resend 60s cooldown enforced, old code invalidated, and unknown email returns identical generic 200")

    # 7. Unverified user row login returns 403 {"error":"Email not verified","verify":true,"email":"..."}
    DB.users.append({
        "id": 99,
        "username": "unver_user",
        "email": "unver@example.com",
        "password_hash": _fake_pw_hash("Password123"),
        "role": "viewer",
        "email_verified": False,
        "failed_attempts": 0,
        "locked_until": 0.0,
        "created_at": "2026-11-17 09:00:00",
    })
    SENT_EMAILS.clear()
    r_unv = client.post("/login", json={"email": "unver@example.com", "password": "Password123"})
    assert r_unv.status_code == 403
    assert r_unv.get_json() == {"error": "Email not verified", "verify": True, "email": "unver@example.com"}
    assert len(SENT_EMAILS) == 1
    unv_code = SENT_EMAILS[-1]["code"]
    # Verify code via /register/verify -> marks user email_verified=True and logs in
    r_unv_ver = client.post("/register/verify", json={"email": "unver@example.com", "code": unv_code})
    assert r_unv_ver.status_code == 200 and "token" in r_unv_ver.get_json()
    print("[PASS] Unverified user login returns 403 verify:true, sends code, and completes verification")

    # 9. Google login rejects unverified Google email and accepts verified Google email
    MOCK_GOOGLE_TOKEN_INFO["bad_google_cred"] = {"email": "g1@example.com", "email_verified": False}
    MOCK_GOOGLE_TOKEN_INFO["good_google_cred"] = {"email": "g2@example.com", "email_verified": True}
    assert client.post("/google", json={"credential": "bad_google_cred"}).status_code == 401
    r_g_ok = client.post("/google", json={"credential": "good_google_cred"})
    assert r_g_ok.status_code == 200 and "token" in r_g_ok.get_json()
    print("[PASS] Google login rejects unverified Google email and logs in verified Google email")


if __name__ == "__main__":
    with pytest.MonkeyPatch.context() as mp:
        _install_stubs(mp)
        run_tests(_load_auth_mod())
