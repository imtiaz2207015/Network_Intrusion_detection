import hmac, os, sqlite3
from datetime import datetime, timezone
from functools import wraps

import jwt
from flask import Flask, request, jsonify, g

app = Flask(__name__)
DB = os.environ.get("DB_PATH", "/data/alerts.db")
SECRET = os.environ["JWT_SECRET"]
SENSOR_KEY = os.environ["SENSOR_KEY"]


def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    con = sqlite3.connect(DB)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS alerts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      time TEXT NOT NULL,
      type TEXT NOT NULL,
      src TEXT NOT NULL,
      dst TEXT, dport TEXT, detail TEXT,
      status TEXT NOT NULL DEFAULT 'new');
    CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(time);
    CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src);
    """)
    con.commit()
    con.close()


init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    con = g.pop("db", None)
    if con:
        con.close()


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


def num(name, default, lo, hi):
    try:
        return max(lo, min(int(request.args.get(name, default)), hi))
    except ValueError:
        return default


@app.post("/ingest")
def ingest():
    key = request.headers.get("X-Service-Key", "")
    if not hmac.compare_digest(key, SENSOR_KEY):
        return jsonify(error="Unauthorized"), 401
    d = request.get_json(silent=True) or {}
    atype = str(d.get("type", "")).strip()[:40]
    src = str(d.get("src", "")).strip()[:64]
    if not atype or not src:
        return jsonify(error="type and src are required"), 400
    t = str(d.get("time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))[:19]
    db().execute(
        "INSERT INTO alerts(time,type,src,dst,dport,detail) VALUES(?,?,?,?,?,?)",
        (t, atype, src, str(d.get("dst", "-"))[:64],
         str(d.get("dport", "-"))[:10], str(d.get("detail", ""))[:300]))
    db().commit()
    return jsonify(ok=True), 201


@app.get("/")
@auth_required()
def list_alerts():
    a = request.args
    where, params = [], []
    if a.get("type"):
        where.append("type LIKE ?")
        params.append(a["type"] + "%")
    if a.get("status"):
        where.append("status = ?")
        params.append(a["status"])
    if a.get("q"):
        like = "%" + a["q"] + "%"
        where.append("(type LIKE ? OR src LIKE ? OR dst LIKE ? OR detail LIKE ?)")
        params += [like] * 4
    w = ("WHERE " + " AND ".join(where)) if where else ""
    limit = num("limit", 50, 1, 200)
    offset = num("offset", 0, 0, 10**9)
    con = db()
    total = con.execute(f"SELECT COUNT(*) FROM alerts {w}", params).fetchone()[0]
    rows = con.execute(
        f"SELECT * FROM alerts {w} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset]).fetchall()
    return jsonify(alerts=[dict(r) for r in rows], total=total)


@app.get("/stats")
@auth_required()
def stats():
    con = db()
    counts = {r["type"]: r["n"] for r in
              con.execute("SELECT type, COUNT(*) n FROM alerts GROUP BY type")}
    sources = [[r["src"], r["n"]] for r in con.execute(
        "SELECT src, COUNT(*) n FROM alerts GROUP BY src ORDER BY n DESC LIMIT 5")]
    total = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return jsonify(total=total, counts=counts, sources=sources)