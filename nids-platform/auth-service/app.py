import os, re, sqlite3, time
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DB = os.environ.get("DB_PATH", "/data/auth.db")
SECRET = os.environ["JWT_SECRET"]
MAX_FAILS = 5
LOCK_SECONDS = 600
ROLES = ("admin", "analyst", "viewer")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    con = sqlite3.connect(DB)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'viewer',
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until REAL NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS login_log(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT, ip TEXT, success INTEGER, at TEXT);
    """)
    con.commit()
    con.close()


init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


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
    if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        return jsonify(error="Password: at least 8 characters with letters and numbers"), 400
    con = db()
    first = con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    role = "admin" if first else "viewer"
    try:
        con.execute(
            "INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
            (username, email, generate_password_hash(pw), role, now_iso()))
        con.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username or email already exists"), 409
    return jsonify(ok=True, role=role), 201


@app.post("/login")
def login():
    d = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip()
    pw = d.get("password") or ""
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    con = db()
    u = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    def log(ok):
        con.execute("INSERT INTO login_log(username,ip,success,at) VALUES(?,?,?,?)",
                    (username, ip, int(ok), now_iso()))
        con.commit()

    if u and u["locked_until"] > time.time():
        log(False)
        return jsonify(error="Account locked. Try again in a few minutes."), 423
    if not u or not check_password_hash(u["password_hash"], pw):
        if u:
            fails = u["failed_attempts"] + 1
            locked = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
            con.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                        (0 if locked else fails, locked, u["id"]))
            con.commit()
        log(False)
        return jsonify(error="Wrong username or password"), 401
    con.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (u["id"],))
    con.commit()
    log(True)
    return jsonify(token=make_token(u), user={"username": u["username"], "role": u["role"]})


@app.get("/me")
@auth_required()
def me():
    return jsonify(username=g.user["username"], role=g.user["role"])


@app.get("/users")
@auth_required("admin")
def users():
    rows = db().execute("SELECT id,username,email,role,created_at FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.put("/users/<int:uid>/role")
@auth_required("admin")
def set_role(uid):
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in ROLES:
        return jsonify(error="Role must be admin, analyst or viewer"), 400
    db().execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    db().commit()
    return jsonify(ok=True)