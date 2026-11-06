import os, re, time, secrets, hashlib, hmac, smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

import jwt
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

app = Flask(__name__)
DSN = os.environ["DATABASE_URL"]
SECRET = os.environ["JWT_SECRET"]
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_APP_PASSWORD = os.environ.get("SMTP_APP_PASSWORD", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:8088").rstrip("/")
MAX_FAILS = 5
LOCK_SECONDS = 600
RESET_SECONDS = 900          # reset link valid for 15 minutes
ROLES = ("admin", "analyst", "viewer")
CODE_SECONDS = 600
CODE_COOLDOWN = 60
CODE_MAX_TRIES = 5


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def connect():
    return psycopg2.connect(DSN, cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    con = None
    for _ in range(30):                      # wait for the database to be ready
        try:
            con = connect()
            break
        except psycopg2.OperationalError:
            time.sleep(1)
    if con is None:
        raise RuntimeError("Database not reachable")
    cur = con.cursor()
    cur.execute("SELECT pg_advisory_lock(42)")   # stops 2 workers creating tables at once
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'viewer',
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until DOUBLE PRECISION NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS login_log(
      id SERIAL PRIMARY KEY,
      username TEXT, ip TEXT, success INTEGER, logged_at TEXT);
    CREATE TABLE IF NOT EXISTS password_resets(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
            expires_at DOUBLE PRECISION NOT NULL);
    CREATE TABLE IF NOT EXISTS password_change_codes(
      user_id INTEGER PRIMARY KEY,
      code_hash TEXT NOT NULL,
      new_hash TEXT NOT NULL,
      expires_at DOUBLE PRECISION NOT NULL,
      sent_at DOUBLE PRECISION NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0);
    """)
    con.commit()
    con.close()


init_db()


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


def query(sql, params=()):
    cur = db().cursor()
    cur.execute(sql, params)
    return cur


@app.teardown_appcontext
def close_db(_):
    con = g.pop("db", None)
    if con:
        con.close()


def make_token(u):
    payload = {
        "sub": str(u["id"]),
        "username": u["username"],
        "role": u["role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


def auth_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **kw):
            h = request.headers.get("Authorization", "")
            if not h.startswith("Bearer "):
                return jsonify(error="Unauthorized"), 401
            try:
                u = jwt.decode(h[7:], SECRET, algorithms=["HS256"])
            except jwt.PyJWTError:
                return jsonify(error="Invalid or expired token"), 401
            if roles and u["role"] not in roles:
                return jsonify(error="Forbidden"), 403
            g.user = u
            return fn(*a, **kw)
        return wrap
    return deco


def valid_password(pw):
    return len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


def unique_username(base):
    base = re.sub(r"[^A-Za-z0-9_]", "", base)[:16] or "user"
    if len(base) < 3:
        base += "user"
    name = base
    while query("SELECT 1 FROM users WHERE username=%s", (name,)).fetchone():
        name = f"{base}{secrets.randbelow(10000)}"
    return name


def send_mail(to, subject, body):
    msg = EmailMessage()
    msg["From"] = f"NIDS Platform <{SMTP_USER}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as s:
        s.login(SMTP_USER, SMTP_APP_PASSWORD)
        s.send_message(msg)


@app.post("/register")
def register():
    d = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip()
    email = (d.get("email") or "").strip().lower()
    pw = d.get("password") or ""
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
        return jsonify(error="Username: 3-20 letters, numbers or _"), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify(error="Invalid email address"), 400
    if not valid_password(pw):
        return jsonify(error="Password: at least 8 characters with letters and numbers"), 400
    first = query("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0
    role = "admin" if first else "viewer"
    try:
        query(
            "INSERT INTO users(username,email,password_hash,role,created_at) VALUES(%s,%s,%s,%s,%s)",
            (username, email, generate_password_hash(pw), role, now_iso()))
        db().commit()
    except psycopg2.IntegrityError:
        db().rollback()
        return jsonify(error="Username or email already exists"), 409
    return jsonify(ok=True, role=role), 201


@app.post("/login")
def login():
    d = request.get_json(silent=True) or {}
    ident = (d.get("username") or d.get("email") or "").strip()
    pw = d.get("password") or ""
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    u = query("SELECT * FROM users WHERE lower(email)=lower(%s) OR username=%s",
              (ident, ident)).fetchone()
    username = u["username"] if u else ident

    def log(ok):
        query("INSERT INTO login_log(username,ip,success,logged_at) VALUES(%s,%s,%s,%s)",
              (username, ip, int(ok), now_iso()))
        db().commit()

    if u and u["locked_until"] > time.time():
        log(False)
        return jsonify(error="Account locked. Try again in a few minutes."), 423
    if not u or not check_password_hash(u["password_hash"], pw):
        if u:
            fails = u["failed_attempts"] + 1
            locked = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
            query("UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s",
                  (0 if locked else fails, locked, u["id"]))
            db().commit()
        log(False)
        return jsonify(error="Wrong email or password"), 401
    query("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=%s", (u["id"],))
    db().commit()
    log(True)
    return jsonify(token=make_token(u), user={"username": u["username"], "role": u["role"]})


@app.get("/google-config")
def google_config():
    return jsonify(client_id=GOOGLE_CLIENT_ID)


@app.post("/google")
def google_login():
    cred = (request.get_json(silent=True) or {}).get("credential") or ""
    if not GOOGLE_CLIENT_ID:
        return jsonify(error="Google login is not configured"), 503
    if not cred:
        return jsonify(error="Missing Google credential"), 400
    try:
        info = id_token.verify_oauth2_token(
            cred, grequests.Request(), GOOGLE_CLIENT_ID, clock_skew_in_seconds=10)
    except ValueError:
        return jsonify(error="Invalid Google token"), 401
    if not info.get("email") or not info.get("email_verified"):
        return jsonify(error="Google email not verified"), 401
    email = info["email"].lower()
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    u = query("SELECT * FROM users WHERE email=%s", (email,)).fetchone()
    if not u:
        first = query("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0
        role = "admin" if first else "viewer"
        username = unique_username(email.split("@")[0])
        # random unusable password: Google users sign in with Google (or set one via reset)
        u = query(
            "INSERT INTO users(username,email,password_hash,role,created_at) "
            "VALUES(%s,%s,%s,%s,%s) RETURNING *",
            (username, email, generate_password_hash(secrets.token_urlsafe(32)),
             role, now_iso())).fetchone()
    query("INSERT INTO login_log(username,ip,success,logged_at) VALUES(%s,%s,%s,%s)",
          (u["username"], ip, 1, now_iso()))
    db().commit()
    return jsonify(token=make_token(u), user={"username": u["username"], "role": u["role"]})


@app.post("/forgot-password")
def forgot_password():
    email = ((request.get_json(silent=True) or {}).get("email") or "").strip().lower()
    reply = jsonify(ok=True, message="If that email is registered, a reset link has been sent.")
    u = query("SELECT id,username FROM users WHERE email=%s", (email,)).fetchone()
    if u:
        token = secrets.token_urlsafe(32)
        th = hashlib.sha256(token.encode()).hexdigest()
        query("DELETE FROM password_resets WHERE user_id=%s", (u["id"],))
        query("INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES(%s,%s,%s)",
              (u["id"], th, time.time() + RESET_SECONDS))
        db().commit()
        link = f"{FRONTEND_URL}/reset-password?token={token}"
        try:
            send_mail(email, "Reset your NIDS password",
                      f"Hi {u['username']},\n\nClick the link below to set a new password. "
                      f"It expires in 15 minutes.\n\n{link}\n\n"
                      "If you did not ask for this, ignore this email.")
        except Exception as e:
            app.logger.error("Reset email failed: %s", e)
    return reply


@app.post("/reset-password")
def reset_password():
    d = request.get_json(silent=True) or {}
    token = d.get("token") or ""
    pw = d.get("password") or ""
    if not valid_password(pw):
        return jsonify(error="Password: at least 8 characters with letters and numbers"), 400
    th = hashlib.sha256(token.encode()).hexdigest()
    r = query("SELECT * FROM password_resets WHERE token_hash=%s", (th,)).fetchone()
    if not r or r["expires_at"] < time.time():
        return jsonify(error="Reset link is invalid or has expired"), 400
    query("UPDATE users SET password_hash=%s, failed_attempts=0, locked_until=0 WHERE id=%s",
          (generate_password_hash(pw), r["user_id"]))
    query("DELETE FROM password_resets WHERE user_id=%s", (r["user_id"],))
    db().commit()
    return jsonify(ok=True)


@app.get("/me")
@auth_required()
def me():
    return jsonify(username=g.user["username"], role=g.user["role"])


@app.get("/users")
@auth_required("admin")
def users():
    rows = query("SELECT id,username,email,role,created_at FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.put("/users/<int:uid>/role")
@auth_required("admin")
def set_role(uid):
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in ROLES:
        return jsonify(error="Role must be admin, analyst or viewer"), 400
    query("UPDATE users SET role=%s WHERE id=%s", (role, uid))
    db().commit()
    return jsonify(ok=True)
def hash_code(uid, code):
    return hashlib.sha256(f"{uid}:{code}:{SECRET}".encode()).hexdigest()


def mask_email(e):
    name, _, dom = e.partition("@")
    return name[:2] + "***@" + dom


def check_current(u, current):
    if u["locked_until"] > time.time():
        return jsonify(error="Too many wrong attempts. Try again in a few minutes."), 423
    if not check_password_hash(u["password_hash"], current):
        fails = u["failed_attempts"] + 1
        locked = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
        query("UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s",
              (0 if locked else fails, locked, u["id"]))
        db().commit()
        return jsonify(error="Current password is incorrect"), 400
    return None


@app.post("/change-password/request")
@auth_required()
def change_password_request():
    d = request.get_json(silent=True) or {}
    current = d.get("current_password") or ""
    new = d.get("new_password") or ""
    u = query("SELECT * FROM users WHERE id=%s", (int(g.user["sub"]),)).fetchone()
    if not u:
        return jsonify(error="User not found"), 404
    bad = check_current(u, current)
    if bad:
        return bad
    if not valid_password(new):
        return jsonify(error="Password: at least 8 characters with letters and numbers"), 400
    if check_password_hash(u["password_hash"], new):
        return jsonify(error="New password must be different from the current one"), 400
    row = query("SELECT sent_at FROM password_change_codes WHERE user_id=%s",
                (u["id"],)).fetchone()
    if row and time.time() - row["sent_at"] < CODE_COOLDOWN:
        return jsonify(error="Please wait a minute before asking for a new code"), 429

    code = f"{secrets.randbelow(1000000):06d}"
    now = time.time()
    query("""INSERT INTO password_change_codes(user_id,code_hash,new_hash,expires_at,sent_at,attempts)
             VALUES(%s,%s,%s,%s,%s,0)
             ON CONFLICT (user_id) DO UPDATE SET
               code_hash=EXCLUDED.code_hash, new_hash=EXCLUDED.new_hash,
               expires_at=EXCLUDED.expires_at, sent_at=EXCLUDED.sent_at, attempts=0""",
          (u["id"], hash_code(u["id"], code), generate_password_hash(new),
           now + CODE_SECONDS, now))
    db().commit()
    try:
        send_mail(u["email"], "Your NIDS password change code",
                  f"Hi {u['username']},\n\nYour verification code is: {code}\n\n"
                  "It expires in 10 minutes. If you did not ask to change your "
                  "password, ignore this email and change your password.")
    except Exception as e:
        app.logger.error("Change-password email failed: %s", e)
        query("DELETE FROM password_change_codes WHERE user_id=%s", (u["id"],))
        db().commit()
        return jsonify(error="Could not send the email. Try again later."), 502
    return jsonify(ok=True, email=mask_email(u["email"]))


@app.post("/change-password/confirm")
@auth_required()
def change_password_confirm():
    code = str((request.get_json(silent=True) or {}).get("code") or "").strip()
    uid = int(g.user["sub"])
    r = query("SELECT * FROM password_change_codes WHERE user_id=%s", (uid,)).fetchone()
    if not r or r["expires_at"] < time.time():
        return jsonify(error="Code expired. Ask for a new one."), 400
    if r["attempts"] >= CODE_MAX_TRIES:
        query("DELETE FROM password_change_codes WHERE user_id=%s", (uid,))
        db().commit()
        return jsonify(error="Too many wrong codes. Ask for a new one."), 400
    if not hmac.compare_digest(r["code_hash"], hash_code(uid, code)):
        query("UPDATE password_change_codes SET attempts=attempts+1 WHERE user_id=%s", (uid,))
        db().commit()
        return jsonify(error="Wrong code"), 400
    query("UPDATE users SET password_hash=%s, failed_attempts=0, locked_until=0 WHERE id=%s",
          (r["new_hash"], uid))
    query("DELETE FROM password_change_codes WHERE user_id=%s", (uid,))
    db().commit()
    return jsonify(ok=True)