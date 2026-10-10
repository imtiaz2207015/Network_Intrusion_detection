import re

import pytest

PW = "Passw0rd123"


def register(c, username="alice", email="alice@example.com", password=PW):
    return c.post("/register", json={"username": username, "email": email, "password": password})


def login(c, ident, password=PW):
    return c.post("/login", json={"username": ident, "password": password})


def bearer(c, ident="alice", password=PW):
    token = login(c, ident, password).get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


# ---------- registration ----------
def test_first_user_is_admin_and_next_is_viewer(auth_client):
    assert register(auth_client).get_json()["role"] == "admin"
    r = register(auth_client, "bob", "bob@example.com")
    assert r.status_code == 201
    assert r.get_json()["role"] == "viewer"


@pytest.mark.parametrize("password", ["short1", "onlyletters", "12345678"])
def test_register_rejects_weak_password(auth_client, password):
    assert register(auth_client, password=password).status_code == 400


@pytest.mark.parametrize("email", ["nope", "a@b", "a b@c.com"])
def test_register_rejects_bad_email(auth_client, email):
    assert register(auth_client, email=email).status_code == 400


def test_register_rejects_bad_username(auth_client):
    assert register(auth_client, username="a b").status_code == 400


def test_duplicate_user_returns_409(auth_client):
    register(auth_client)
    assert register(auth_client).status_code == 409


# ---------- login ----------
def test_login_with_email_or_username(auth_client):
    register(auth_client)
    for ident in ("alice@example.com", "ALICE@example.com", "alice"):
        r = login(auth_client, ident)
        assert r.status_code == 200
        assert r.get_json()["user"]["username"] == "alice"


def test_wrong_password_is_401(auth_client):
    register(auth_client)
    assert login(auth_client, "alice", "WrongPass1").status_code == 401
    assert login(auth_client, "ghost@example.com").status_code == 401


def test_account_locks_after_five_failures(auth_client):
    register(auth_client)
    for _ in range(5):
        assert login(auth_client, "alice", "WrongPass1").status_code == 401
    assert login(auth_client, "alice").status_code == 423      # even the right password


# ---------- tokens and roles ----------
def test_me_needs_a_valid_token(auth_client):
    register(auth_client)
    assert auth_client.get("/me").status_code == 401
    assert auth_client.get("/me", headers={"Authorization": "Bearer junk"}).status_code == 401
    r = auth_client.get("/me", headers=bearer(auth_client))
    assert r.status_code == 200 and r.get_json()["username"] == "alice"


def test_users_list_is_admin_only(auth_client):
    register(auth_client)
    register(auth_client, "bob", "bob@example.com")
    assert auth_client.get("/users", headers=bearer(auth_client, "bob")).status_code == 403
    r = auth_client.get("/users", headers=bearer(auth_client, "alice"))
    assert r.status_code == 200 and len(r.get_json()) == 2
    assert "password_hash" not in r.get_data(as_text=True)


def test_admin_can_change_role(auth_client):
    register(auth_client)
    register(auth_client, "bob", "bob@example.com")
    admin = bearer(auth_client, "alice")
    users = auth_client.get("/users", headers=admin).get_json()
    bob_id = next(u["id"] for u in users if u["username"] == "bob")
    assert auth_client.put(f"/users/{bob_id}/role", json={"role": "analyst"}, headers=admin).status_code == 200
    assert auth_client.put(f"/users/{bob_id}/role", json={"role": "root"}, headers=admin).status_code == 400
    assert login(auth_client, "bob").get_json()["user"]["role"] == "analyst"


# ---------- Google login ----------
def fake_google(result):
    def _verify(cred, request, client_id, **kw):
        if isinstance(result, Exception):
            raise result
        return result
    return _verify


def test_google_is_off_without_client_id(auth_client):
    assert auth_client.post("/google", json={"credential": "x"}).status_code == 503


def test_google_login_creates_then_reuses_account(auth, auth_client, monkeypatch):
    monkeypatch.setattr(auth, "GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setattr(auth.id_token, "verify_oauth2_token",
                        fake_google({"email": "Bob@Example.com", "email_verified": True}))
    first = auth_client.post("/google", json={"credential": "x"})
    assert first.status_code == 200
    assert first.get_json()["user"]["username"] == "bob"
    second = auth_client.post("/google", json={"credential": "x"})
    assert second.get_json()["user"]["username"] == "bob"
    users = auth_client.get("/users", headers={"Authorization": "Bearer " + first.get_json()["token"]})
    assert len(users.get_json()) == 1                         # same account, not a duplicate


def test_google_rejects_unverified_email_and_bad_token(auth, auth_client, monkeypatch):
    monkeypatch.setattr(auth, "GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setattr(auth.id_token, "verify_oauth2_token",
                        fake_google({"email": "a@b.com", "email_verified": False}))
    assert auth_client.post("/google", json={"credential": "x"}).status_code == 401
    monkeypatch.setattr(auth.id_token, "verify_oauth2_token", fake_google(ValueError("bad")))
    assert auth_client.post("/google", json={"credential": "x"}).status_code == 401
    assert auth_client.post("/google", json={}).status_code == 400


# ---------- forgot / reset password ----------
@pytest.fixture()
def outbox(auth, monkeypatch):
    sent = []
    monkeypatch.setattr(auth, "send_mail", lambda to, subject, body: sent.append((to, body)))
    return sent


def token_from(outbox):
    return re.search(r"token=([\w-]+)", outbox[-1][1]).group(1)


def test_forgot_password_does_not_reveal_unknown_emails(auth_client, outbox):
    register(auth_client)
    known = auth_client.post("/forgot-password", json={"email": "alice@example.com"})
    unknown = auth_client.post("/forgot-password", json={"email": "ghost@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.get_json() == unknown.get_json()
    assert len(outbox) == 1                                   # only the real user got mail


def test_password_reset_flow(auth_client, outbox):
    register(auth_client)
    auth_client.post("/forgot-password", json={"email": "alice@example.com"})
    token = token_from(outbox)
    assert auth_client.post("/reset-password", json={"token": token, "password": "short"}).status_code == 400
    assert auth_client.post("/reset-password", json={"token": token, "password": "NewPassw0rd9"}).status_code == 200
    assert login(auth_client, "alice").status_code == 401                 # old password is dead
    assert login(auth_client, "alice", "NewPassw0rd9").status_code == 200
    again = auth_client.post("/reset-password", json={"token": token, "password": "Another1Pass"})
    assert again.status_code == 400                                       # a link works only once


def test_expired_reset_link_is_rejected(auth, auth_client, outbox):
    register(auth_client)
    auth_client.post("/forgot-password", json={"email": "alice@example.com"})
    con = auth.connect()
    con.cursor().execute("UPDATE password_resets SET expires_at = 0")
    con.commit()
    con.close()
    r = auth_client.post("/reset-password", json={"token": token_from(outbox), "password": "NewPassw0rd9"})
    assert r.status_code == 400