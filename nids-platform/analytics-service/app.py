import io, os
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo

import jwt
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, g, send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

app = Flask(__name__)
DSN = os.environ["DATABASE_URL"]
SECRET = os.environ["JWT_SECRET"]
SENSOR_TZ = os.environ.get("SENSOR_TZ", "Asia/Dhaka")   # timezone the Pi writes alert times in
FMT = "%Y-%m-%d %H:%M:%S"

# Same rules as severity() in the frontend utils.js
def sev(t):
    t = (t or "").lower()
    if "dos" in t or "syn" in t:
        return "Critical"
    if "brute" in t or "udp" in t or "icmp" in t:
        return "High"
    return "Medium"


def db():
    if "db" not in g:
        g.db = psycopg2.connect(DSN, cursor_factory=psycopg2.extras.RealDictCursor)
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


def hours_arg():
    try:
        return max(1, min(int(request.args.get("hours", 24)), 720))
    except ValueError:
        return 24


def collect(hours):
    """Stats for the last N hours, counted back from NOW in the sensor's timezone."""
    blen = 16 if hours <= 1 else 13 if hours <= 24 else 10
    bucket = {16: "minute", 13: "hour", 10: "day"}[blen]
    end = datetime.now(ZoneInfo(SENSOR_TZ)).replace(tzinfo=None)
    m = end.strftime(FMT)
    start = (end - timedelta(hours=hours)).strftime(FMT)
    p = (start,)
    by_type = {r["type"]: r["n"] for r in query(
        "SELECT type, COUNT(*) AS n FROM alerts WHERE time >= %s GROUP BY type ORDER BY n DESC", p)}
    by_sev = {}
    for t, n in by_type.items():
        by_sev[sev(t)] = by_sev.get(sev(t), 0) + n
    sources = [[r["src"], r["n"]] for r in query(
        "SELECT src, COUNT(*) AS n FROM alerts WHERE time >= %s GROUP BY src ORDER BY n DESC LIMIT 5", p)]
    top_ports = [[r["dport"], r["n"]] for r in query(
        "SELECT dport, COUNT(*) AS n FROM alerts WHERE time >= %s AND dport NOT IN ('-','') "
        "GROUP BY dport ORDER BY n DESC LIMIT 5", p)]
    top_targets = [[r["dst"], r["n"]] for r in query(
        "SELECT dst, COUNT(*) AS n FROM alerts WHERE time >= %s AND dst NOT IN ('-','') "
        "GROUP BY dst ORDER BY n DESC LIMIT 5", p)]
    u = query("SELECT COUNT(DISTINCT src) AS s, COUNT(DISTINCT NULLIF(NULLIF(dst,'-'),'')) AS t "
              "FROM alerts WHERE time >= %s", p).fetchone()
    timeline = [{"hour": r["h"], "count": r["n"]} for r in query(
        "SELECT SUBSTRING(time,1,%s) AS h, COUNT(*) AS n FROM alerts WHERE time >= %s GROUP BY h ORDER BY h",
        (blen, start))]
    recent = [dict(r) for r in query(
        "SELECT time, type, src, dst, dport FROM alerts WHERE time >= %s ORDER BY id DESC LIMIT 15", p)]
    return dict(hours=hours, range={"from": start, "to": m}, bucket=bucket,
                total=sum(by_type.values()), by_type=by_type, by_severity=by_sev,
                sources=sources, top_ports=top_ports, top_targets=top_targets,
                unique_sources=u["s"], unique_targets=u["t"],
                timeline=timeline, recent=recent)


@app.get("/summary")
@auth_required()
def summary():
    return jsonify(collect(hours_arg()))


def pdf_table(data, widths=None):
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1b3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
    ]))
    return t


def bar_chart(by_type):
    dr = Drawing(450, 200)
    ch = VerticalBarChart()
    ch.x, ch.y, ch.width, ch.height = 40, 30, 380, 140
    ch.data = [list(by_type.values())]
    ch.categoryAxis.categoryNames = list(by_type.keys())
    ch.categoryAxis.labels.fontSize = 7
    ch.valueAxis.valueMin = 0
    ch.valueAxis.valueStep = max(1, round(max(by_type.values()) / 5))
    ch.bars[0].fillColor = colors.HexColor("#06b6d4")
    dr.add(ch)
    return dr


@app.get("/report.pdf")
@auth_required()
def report_pdf():
    d = collect(hours_arg())
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm, title="NIDS.AI Security Report")
    st = getSampleStyleSheet()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    el = [Paragraph("NIDS.AI Security Report", st["Title"]),
          Paragraph(f"Generated {now} UTC by {g.user['username']}", st["Normal"]),
          Paragraph(f"Period: last {d['hours']} h ({d['range']['from']} to {d['range']['to']}, sensor time)", st["Normal"]),
          Spacer(1, 12)]
    if not d["total"]:
        el.append(Paragraph("No alerts recorded in this period.", st["Normal"]))
    else:
        el += [Paragraph(f"Total alerts: <b>{d['total']}</b>", st["Normal"]),
               Spacer(1, 12), Paragraph("Alerts by type", st["Heading2"]),
               bar_chart(d["by_type"]),
               pdf_table([["Attack type", "Severity", "Count"]] +
                         [[t, sev(t), n] for t, n in d["by_type"].items()]),
               Spacer(1, 12), Paragraph("Top source IPs", st["Heading2"]),
               pdf_table([["Source IP", "Alerts"]] + d["sources"]),
               Spacer(1, 12), Paragraph("Most recent alerts", st["Heading2"]),
               pdf_table([["Time", "Type", "Source", "Target", "Port"]] +
                         [[r["time"], r["type"], r["src"], r["dst"], r["dport"]] for r in d["recent"]])]
    doc.build(el)
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf", as_attachment=True,
                     download_name="nids-report.pdf")