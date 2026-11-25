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
OWNER_EMAIL = os.environ.get("OWNER_EMAIL", "") or SMTP_USER   # support messages go here
PUBLIC_BASE_URL = (
    os.environ.get("PUBLIC_BASE_URL")
    or os.environ.get("FRONTEND_URL")
    or "http://localhost:8088"
).rstrip("/")
FRONTEND_URL = PUBLIC_BASE_URL
# Automated test flag ONLY (never enable in production): skips SMTP on /register and creates verified user directly
TEST_AUTO_VERIFY = os.environ.get("TEST_AUTO_VERIFY", "").strip().lower() in ("1", "true", "yes")

MAX_FAILS = 5
LOCK_SECONDS = 600
RESET_SECONDS = 900          # reset link valid for 15 minutes
ROLES = ("admin", "analyst", "viewer")
CODE_SECONDS = 600           # 6-digit verification code valid for 10 minutes
CODE_COOLDOWN = 60           # 60 seconds between resend requests
CODE_MAX_TRIES = 5           # max 5 wrong code attempts
RESEND_MAX_PER_HOUR = 5      # max 5 verification emails per hour per email
IP_MAX_FAILS = 15
IP_WINDOW_SECONDS = 600      # 10 minutes
REPORT_MAX_PER_HOUR = 5
PW_CHANGE_MAX_PER_HOUR = 10
GOOGLE_PW_PREFIX = "!google!"

DISPOSABLE_DOMAINS = frozenset({
    "mailinator.com",
    "10minutemail.com",
    "guerrillamail.com",
    "tempmail.com",
    "yopmail.com",
    "trashmail.com",
    "sharklasers.com",
    "getnada.com",
    "throwawaymail.com",
})


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def is_disposable_email(email):
    domain = (email or "").rpartition("@")[2].strip().lower()
    if not domain:
        return False
    return any(domain == d or domain.endswith("." + d) for d in DISPOSABLE_DOMAINS)


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
    try:
        cur = con.cursor()
        cur.execute("SELECT pg_advisory_xact_lock(42)")   # stops 2 workers creating tables at once
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
        CREATE TABLE IF NOT EXISTS support_messages(
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL,
          username TEXT NOT NULL,
          email TEXT NOT NULL,
          subject TEXT NOT NULL,
          message TEXT NOT NULL,
          context TEXT,
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS pending_registrations(
          email TEXT PRIMARY KEY,
          username TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          code_hash TEXT NOT NULL,
          expires_at DOUBLE PRECISION NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          last_sent_at DOUBLE PRECISION NOT NULL,
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS registration_send_log(
          id SERIAL PRIMARY KEY,
          email TEXT NOT NULL,
          sent_at DOUBLE PRECISION NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_reg_send_log_email ON registration_send_log(email, sent_at);
        CREATE TABLE IF NOT EXISTS password_change_attempts(
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL,
          attempted_at DOUBLE PRECISION NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_pw_change_attempts_user ON password_change_attempts(user_id, attempted_at);
        """)
        # Idempotent migration: add email_verified to users and mark all pre-existing users true
        cur.execute(
            "SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='email_verified'"
        )
        if not cur.fetchone():
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false")
            cur.execute("UPDATE users SET email_verified = true")
        con.commit()
    finally:
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


def is_google_only_pw(pw_hash):
    return not pw_hash or pw_hash.startswith(GOOGLE_PW_PREFIX)


def verify_user_password(pw_hash, pw):
    if not pw or is_google_only_pw(pw_hash):
        return False
    try:
        return check_password_hash(pw_hash, pw)
    except ValueError:
        return False


def unique_username(base):
    base = re.sub(r"[^A-Za-z0-9_]", "", base)[:16] or "user"
    if len(base) < 3:
        base += "user"
    name = base
    while query("SELECT 1 FROM users WHERE username=%s", (name,)).fetchone():
        name = f"{base}{secrets.randbelow(10000)}"
    return name


def send_mail(to, subject, body, reply_to=None):
    if not SMTP_USER or not SMTP_APP_PASSWORD:
        raise RuntimeError("SMTP credentials (SMTP_USER / SMTP_APP_PASSWORD) are not configured")
    msg = EmailMessage()
    msg["From"] = f"SentinelIQ <{SMTP_USER}>"
    msg["To"] = to
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(body)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as s:
        s.login(SMTP_USER, SMTP_APP_PASSWORD)
        s.send_message(msg)


def hash_reg_code(email, code):
    return hashlib.sha256(f"reg:{email.strip().lower()}:{code}:{SECRET}".encode()).hexdigest()


def send_verification_email(email, username, code):
    send_mail(
        email,
        "Your SentinelIQ verification code",
        f"Hi {username},\n\n"
        f"Your 6-digit verification code is: {code}\n\n"
        f"This code expires in 10 minutes.\n\n"
        f"If you did not create a SentinelIQ account, you can safely ignore this email."
    )


def count_recent_reg_sends(email, now_ts):
    row = query(
        "SELECT COUNT(*) AS n FROM registration_send_log WHERE lower(email)=lower(%s) AND sent_at > %s",
        (email, now_ts - 3600)
    ).fetchone()
    return row["n"] if row else 0


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
    if is_disposable_email(email):
        return jsonify(error="Please use a permanent email address"), 400
    if not valid_password(pw):
        return jsonify(error="Password: at least 8 characters with letters and numbers"), 400

    now = time.time()
    # Clean up expired pending registrations first
    query("DELETE FROM pending_registrations WHERE expires_at < %s", (now,))

    # Check if username or email already belongs to a real user
    existing_user = query(
        "SELECT 1 FROM users WHERE lower(email)=lower(%s) OR username=%s",
        (email, username)
    ).fetchone()
    if existing_user:
        db().commit()
        return jsonify(error="Username or email already exists"), 409

    # Check if another active pending registration holds the same username
    conflict_pending = query(
        "SELECT 1 FROM pending_registrations WHERE username=%s AND lower(email)!=lower(%s)",
        (username, email)
    ).fetchone()
    if conflict_pending:
        db().commit()
        return jsonify(error="Username or email already exists"), 409

    # Automated test bypass (TEST_AUTO_VERIFY=true): create verified user directly
    if TEST_AUTO_VERIFY:
        first = query("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0
        role = "admin" if first else "viewer"
        try:
            query(
                """INSERT INTO users(username,email,password_hash,role,email_verified,created_at)
                   VALUES(%s,%s,%s,%s,true,%s)""",
                (username, email, generate_password_hash(pw), role, now_iso())
            )
            db().commit()
        except psycopg2.IntegrityError:
            db().rollback()
            return jsonify(error="Username or email already exists"), 409
        return jsonify(ok=True, role=role), 201

    # Enforce 60s cooldown and 5/hour rate limit on verification emails
    prev_pending = query("SELECT * FROM pending_registrations WHERE lower(email)=lower(%s)", (email,)).fetchone()
    if prev_pending and now - prev_pending["last_sent_at"] < CODE_COOLDOWN:
        wait_s = max(1, int(CODE_COOLDOWN - (now - prev_pending["last_sent_at"])))
        db().commit()
        return jsonify(error=f"Please wait {wait_s}s before requesting another code"), 429
    if count_recent_reg_sends(email, now) >= RESEND_MAX_PER_HOUR:
        db().commit()
        return jsonify(error="Too many verification codes requested. Try again in an hour."), 429

    code = f"{secrets.randbelow(1000000):06d}"
    pw_hash = generate_password_hash(pw)
    code_hash = hash_reg_code(email, code)

    try:
        send_verification_email(email, username, code)
    except Exception as e:
        db().rollback()
        app.logger.error("Registration verification email failed: %s", e)
        return jsonify(error="Could not send the verification email, try again"), 503

    query(
        """INSERT INTO pending_registrations(
             email, username, password_hash, code_hash, expires_at, attempts, last_sent_at, created_at
           ) VALUES(%s,%s,%s,%s,%s,0,%s,%s)
           ON CONFLICT (email) DO UPDATE SET
             username=EXCLUDED.username,
             password_hash=EXCLUDED.password_hash,
             code_hash=EXCLUDED.code_hash,
             expires_at=EXCLUDED.expires_at,
             attempts=0,
             last_sent_at=EXCLUDED.last_sent_at,
             created_at=EXCLUDED.created_at""",
        (email, username, pw_hash, code_hash, now + CODE_SECONDS, now, now_iso())
    )
    query("INSERT INTO registration_send_log(email, sent_at) VALUES(%s, %s)", (email, now))
    db().commit()
    return jsonify(verify=True, email=email), 200


@app.post("/register/verify")
def register_verify():
    d = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    code = re.sub(r"\D", "", str(d.get("code") or ""))
    if not email or len(code) != 6:
        return jsonify(error="Enter the 6-digit verification code"), 400

    now = time.time()
    r = query("SELECT * FROM pending_registrations WHERE lower(email)=lower(%s)", (email,)).fetchone()
    if not r:
        return jsonify(error="No pending verification found or code expired. Please register again."), 400

    if r["expires_at"] < now:
        query("DELETE FROM pending_registrations WHERE lower(email)=lower(%s)", (email,))
        db().commit()
        return jsonify(error="Verification code has expired. Please register again or resend."), 400

    if r["attempts"] >= CODE_MAX_TRIES:
        query("DELETE FROM pending_registrations WHERE lower(email)=lower(%s)", (email,))
        db().commit()
        return jsonify(error="Too many wrong attempts. Please register again."), 400

    expected_hash = hash_reg_code(email, code)
    if not hmac.compare_digest(r["code_hash"], expected_hash):
        new_attempts = r["attempts"] + 1
        if new_attempts >= CODE_MAX_TRIES:
            query("DELETE FROM pending_registrations WHERE lower(email)=lower(%s)", (email,))
            db().commit()
            return jsonify(error="Too many wrong attempts. Please register again."), 400
        query("UPDATE pending_registrations SET attempts=%s WHERE lower(email)=lower(%s)", (new_attempts, email))
        db().commit()
        left = CODE_MAX_TRIES - new_attempts
        return jsonify(error=f"Wrong verification code ({left} {'attempt' if left == 1 else 'attempts'} left)"), 400

    # Code verified! Check if this is an existing unverified user or a new registration
    existing_u = query("SELECT * FROM users WHERE lower(email)=lower(%s)", (email,)).fetchone()
    if existing_u:
        u = query(
            "UPDATE users SET email_verified=true, failed_attempts=0, locked_until=0 WHERE id=%s RETURNING *",
            (existing_u["id"],)
        ).fetchone()
    else:
        first = query("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0
        role = "admin" if first else "viewer"
        try:
            u = query(
                """INSERT INTO users(username,email,password_hash,role,email_verified,created_at)
                   VALUES(%s,%s,%s,%s,true,%s) RETURNING *""",
                (r["username"], email, r["password_hash"], role, now_iso())
            ).fetchone()
        except psycopg2.IntegrityError:
            db().rollback()
            query("DELETE FROM pending_registrations WHERE lower(email)=lower(%s)", (email,))
            db().commit()
            return jsonify(error="Username or email already exists"), 409

    query("DELETE FROM pending_registrations WHERE lower(email)=lower(%s)", (email,))
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    query("INSERT INTO login_log(username,ip,success,logged_at) VALUES(%s,%s,1,%s)",
          (u["username"], ip, now_iso()))
    db().commit()
    return jsonify(
        token=make_token(u),
        user={"username": u["username"], "role": u["role"], "email": u["email"]},
    ), 200


@app.post("/register/resend")
def register_resend():
    d = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    generic_ok = jsonify(
        ok=True,
        message="If a registration is pending for that email, a new verification code has been sent."
    )
    if not email:
        return generic_ok, 200

    now = time.time()
    r = query("SELECT * FROM pending_registrations WHERE lower(email)=lower(%s)", (email,)).fetchone()
    if not r:
        return generic_ok, 200

    if now - r["last_sent_at"] < CODE_COOLDOWN:
        wait_s = max(1, int(CODE_COOLDOWN - (now - r["last_sent_at"])))
        return jsonify(error=f"Please wait {wait_s}s before requesting another code"), 429

    if count_recent_reg_sends(email, now) >= RESEND_MAX_PER_HOUR:
        return jsonify(error="Too many verification codes requested. Try again in an hour."), 429

    code = f"{secrets.randbelow(1000000):06d}"
    code_hash = hash_reg_code(email, code)
    try:
        send_verification_email(email, r["username"], code)
    except Exception as e:
        app.logger.error("Resend verification email failed: %s", e)
        return jsonify(error="Could not send the verification email, try again"), 503

    query(
        """UPDATE pending_registrations
           SET code_hash=%s, expires_at=%s, attempts=0, last_sent_at=%s
           WHERE lower(email)=lower(%s)""",
        (code_hash, now + CODE_SECONDS, now, email)
    )
    query("INSERT INTO registration_send_log(email, sent_at) VALUES(%s, %s)", (email, now))
    db().commit()
    return generic_ok, 200


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

    recent_fails = query(
        "SELECT COUNT(*) AS n FROM login_log "
        "WHERE ip=%s AND success=0 AND logged_at > %s",
        (ip, datetime.fromtimestamp(time.time() - IP_WINDOW_SECONDS, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    ).fetchone()
    if recent_fails["n"] >= IP_MAX_FAILS:
        return jsonify(error="Too many failed attempts from this network. Try again later."), 429

    if u and u["locked_until"] > time.time():
        log(False)
        return jsonify(error="Account locked. Try again in a few minutes."), 423
    if not u or not verify_user_password(u["password_hash"], pw):
        if u:
            fails = u["failed_attempts"] + 1
            locked = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
            query("UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s",
                  (0 if locked else fails, locked, u["id"]))
            db().commit()
        log(False)
        return jsonify(error="Wrong email or password"), 401

    # Check if user's email is verified
    if not u.get("email_verified", True):
        now = time.time()
        email = u["email"].lower()
        prev = query("SELECT * FROM pending_registrations WHERE lower(email)=lower(%s)", (email,)).fetchone()
        can_send = (not prev or (now - prev["last_sent_at"] >= CODE_COOLDOWN)) and (
            count_recent_reg_sends(email, now) < RESEND_MAX_PER_HOUR
        )
        if can_send:
            code = f"{secrets.randbelow(1000000):06d}"
            code_hash = hash_reg_code(email, code)
            try:
                send_verification_email(email, u["username"], code)
                query(
                    """INSERT INTO pending_registrations(
                         email, username, password_hash, code_hash, expires_at, attempts, last_sent_at, created_at
                       ) VALUES(%s,%s,%s,%s,%s,0,%s,%s)
                       ON CONFLICT (email) DO UPDATE SET
                         code_hash=EXCLUDED.code_hash,
                         expires_at=EXCLUDED.expires_at,
                         attempts=0,
                         last_sent_at=EXCLUDED.last_sent_at""",
                    (email, u["username"], u["password_hash"], code_hash, now + CODE_SECONDS, now, now_iso())
                )
                query("INSERT INTO registration_send_log(email, sent_at) VALUES(%s, %s)", (email, now))
                db().commit()
            except Exception as e:
                db().rollback()
                app.logger.error("Unverified login code send failed: %s", e)
        return jsonify(error="Email not verified", verify=True, email=u["email"]), 403

    query("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=%s", (u["id"],))
    db().commit()
    log(True)
    return jsonify(
        token=make_token(u),
        user={"username": u["username"], "role": u["role"], "email": u["email"]},
    )


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
    if not info.get("email") or info.get("email_verified") is not True:
        return jsonify(error="Google email not verified"), 401
    email = info["email"].lower()
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    u = query("SELECT * FROM users WHERE lower(email)=lower(%s)", (email,)).fetchone()
    if not u:
        first = query("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0
        role = "admin" if first else "viewer"
        username = unique_username(email.split("@")[0])
        try:
            # Marked as Google-created until the user sets a password via Forgot Password
            u = query(
                "INSERT INTO users(username,email,password_hash,role,email_verified,created_at) "
                "VALUES(%s,%s,%s,%s,true,%s) RETURNING *",
                (username, email, GOOGLE_PW_PREFIX + secrets.token_urlsafe(32),
                 role, now_iso())).fetchone()
            db().commit()
        except psycopg2.IntegrityError:
            db().rollback()
            u = query("SELECT * FROM users WHERE lower(email)=lower(%s)", (email,)).fetchone()
            if not u:
                return jsonify(error="Could not complete Google sign-in. Please try again."), 409
    elif not u.get("email_verified", True):
        u = query("UPDATE users SET email_verified=true WHERE id=%s RETURNING *", (u["id"],)).fetchone()
        db().commit()
    query("INSERT INTO login_log(username,ip,success,logged_at) VALUES(%s,%s,%s,%s)",
          (u["username"], ip, 1, now_iso()))
    db().commit()
    return jsonify(
        token=make_token(u),
        user={"username": u["username"], "role": u["role"], "email": u["email"]},
    )


@app.post("/forgot-password")
def forgot_password():
    email = ((request.get_json(silent=True) or {}).get("email") or "").strip().lower()
    reply = jsonify(ok=True, message="If that email is registered, a reset link has been sent.")
    u = query("SELECT id,username,email FROM users WHERE lower(email)=lower(%s)", (email,)).fetchone()
    if u:
        token = secrets.token_urlsafe(32)
        th = hashlib.sha256(token.encode()).hexdigest()
        query("DELETE FROM password_resets WHERE user_id=%s", (u["id"],))
        query("INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES(%s,%s,%s)",
              (u["id"], th, time.time() + RESET_SECONDS))
        db().commit()
        link = f"{FRONTEND_URL}/reset-password?token={token}"
        try:
            send_mail(u["email"], "Reset your SentinelIQ password",
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
    u = query("SELECT id,username,email,role,created_at FROM users WHERE id=%s", (int(g.user["sub"]),)).fetchone()
    if not u:
        return jsonify(username=g.user["username"], role=g.user["role"])
    return jsonify(id=u["id"], username=u["username"], role=u["role"], email=u["email"], created_at=u["created_at"])


@app.get("/users")
@auth_required("admin")
def users():
    rows = query("SELECT id,username,email,role,created_at FROM users ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.put("/users/<int:uid>/role")
@auth_required("admin")
def set_role(uid):
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in ROLES:
        return jsonify(error="Role must be admin, analyst or viewer"), 400
    cur = query("UPDATE users SET role=%s WHERE id=%s", (role, uid))
    db().commit()
    if cur.rowcount == 0:
        return jsonify(error="User not found"), 404
    return jsonify(ok=True)


def hash_code(uid, code):
    return hashlib.sha256(f"{uid}:{code}:{SECRET}".encode()).hexdigest()


def mask_email(e):
    name, _, dom = e.partition("@")
    return name[:2] + "***@" + dom


def check_current(u, current):
    if is_google_only_pw(u["password_hash"]):
        return jsonify(
            error="This account uses Google Sign-In and has no password set yet. "
                  "Use 'Forgot password' on the login page to set one."
        ), 400
    if u["locked_until"] > time.time():
        return jsonify(error="Too many wrong attempts. Try again in a few minutes."), 423
    if not verify_user_password(u["password_hash"], current):
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
    if verify_user_password(u["password_hash"], new):
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
        send_mail(u["email"], "Your SentinelIQ password change code",
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


@app.route("/password", methods=["PUT", "POST"])
@auth_required()
def change_password_direct():
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify(error="Invalid JSON body"), 400
    current = str(d.get("current_password") or "")
    new = str(d.get("new_password") or "")

    uid = int(g.user["sub"])
    u = query("SELECT * FROM users WHERE id=%s", (uid,)).fetchone()
    if not u:
        return jsonify(error="User not found"), 404

    now = time.time()
    recent = query(
        "SELECT COUNT(*) AS n FROM password_change_attempts WHERE user_id=%s AND attempted_at > %s",
        (uid, now - 3600),
    ).fetchone()["n"]
    if recent >= PW_CHANGE_MAX_PER_HOUR:
        return jsonify(error="Too many password change attempts. Please try again in an hour."), 429

    if not current:
        return jsonify(error="Current password is required"), 400

    query("INSERT INTO password_change_attempts(user_id, attempted_at) VALUES(%s, %s)", (uid, now))
    db().commit()

    bad = check_current(u, current)
    if bad:
        return bad
    if len(new) < 8:
        return jsonify(error="New password must be at least 8 characters"), 400
    if verify_user_password(u["password_hash"], new):
        return jsonify(error="New password must be different from the current password"), 400

    query(
        "UPDATE users SET password_hash=%s, failed_attempts=0, locked_until=0 WHERE id=%s",
        (generate_password_hash(new), uid),
    )
    db().commit()
    return jsonify(ok=True)


@app.post("/report")
@auth_required()
def report_problem():
    d = request.get_json(silent=True) or {}
    subject = " ".join(str(d.get("subject") or "").split())   # no newlines in the email subject
    message = str(d.get("message") or "").strip()
    context = " ".join(str(d.get("context") or "").split())
    if not 3 <= len(subject) <= 100:
        return jsonify(error="Subject must be 3-100 characters"), 400
    if not 10 <= len(message) <= 1000:
        return jsonify(error="Message must be 10-1000 characters"), 400
    if len(context) > 200:
        return jsonify(error="Related alert/IP is too long (max 200 characters)"), 400

    uid = int(g.user["sub"])
    u = query("SELECT id,username,email FROM users WHERE id=%s", (uid,)).fetchone()
    if not u:
        return jsonify(error="User not found"), 404

    since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    sent = query("SELECT COUNT(*) AS n FROM support_messages WHERE user_id=%s AND created_at > %s",
                 (uid, since)).fetchone()["n"]
    if sent >= REPORT_MAX_PER_HOUR:
        return jsonify(error="You have sent too many reports. Please try again in an hour."), 429

    row = query(
        "INSERT INTO support_messages(user_id,username,email,subject,message,context,created_at) "
        "VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (uid, u["username"], u["email"], subject, message, context or None, now_iso())).fetchone()
    db().commit()

    emailed = False
    if OWNER_EMAIL and SMTP_USER and SMTP_APP_PASSWORD:
        body = (f"New problem report #{row['id']}\n\n"
                f"From: {u['username']} <{u['email']}> (role: {g.user['role']})\n"
                f"Related alert/IP: {context or '-'}\n\n"
                f"{message}\n\n"
                "Reply to this email to answer the user directly.")
        try:
            send_mail(OWNER_EMAIL, f"[SentinelIQ support #{row['id']}] {subject}",
                      body, reply_to=u["email"])
            emailed = True
        except Exception as e:
            app.logger.error("Support email failed: %s", e)
    return jsonify(ok=True, id=row["id"], emailed=emailed), 201
