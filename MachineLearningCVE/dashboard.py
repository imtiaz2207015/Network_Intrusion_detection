from flask import Flask, jsonify
import csv, os
from collections import Counter

app = Flask(__name__)
ALERT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts.csv")

def read_alerts():
    if not os.path.exists(ALERT_FILE):
        return []
    with open(ALERT_FILE, newline="") as f:
        return list(csv.DictReader(f))

@app.route("/api/alerts")
def api_alerts():
    rows = read_alerts()
    counts = dict(Counter(r["type"] for r in rows))
    return jsonify({"alerts": rows[::-1][:200], "counts": counts, "total": len(rows)})

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NIDS Dashboard</title>
<style>
:root{--bg:#0b1020;--panel:#121a30;--line:#1f2b4d;--text:#e8ecff;--muted:#8b97b8;
--dos:#ff5c7a;--brute:#ffb020;--scan:#4cc9f0;--ml:#a78bfa;--ok:#34d399}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#1b2a5a 0%,var(--bg) 60%);
color:var(--text);font-family:Inter,"Segoe UI",system-ui,sans-serif;min-height:100vh}
.wrap{max-width:1150px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
h1{margin:0;font-size:26px;letter-spacing:.3px;
background:linear-gradient(90deg,#fff,#7aa2ff);-webkit-background-clip:text;color:transparent}
.sub{color:var(--muted);font-size:13px;margin-top:4px}
.status{display:flex;align-items:center;gap:8px;background:var(--panel);border:1px solid var(--line);
padding:8px 14px;border-radius:999px;font-size:13px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--ok);animation:pulse 1.6s infinite}
.dot.off{background:var(--dos);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,211,153,.6)}100%{box-shadow:0 0 0 10px rgba(52,211,153,0)}}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin:24px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;
position:relative;overflow:hidden}
.card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--c,#7aa2ff)}
.card .n{font-size:34px;font-weight:700;margin-top:6px}
.card .l{color:var(--muted);font-size:13px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:18px}
.panel h2{margin:0 0 14px;font-size:15px;color:var(--muted);font-weight:600;letter-spacing:.5px;text-transform:uppercase}
.bars{display:flex;align-items:flex-end;gap:8px;height:120px}
.col{flex:1;height:100%;display:flex;flex-direction:column-reverse;background:#0e1730;border-radius:6px;overflow:hidden}
.seg{width:100%}
.axis{display:flex;justify-content:space-between;color:var(--muted);font-size:11px;margin-top:6px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.chip{background:#0e1730;border:1px solid var(--line);color:var(--muted);padding:6px 14px;
border-radius:999px;font-size:13px;cursor:pointer}
.chip.on{background:#22336b;color:#fff;border-color:#4b64c8}
.alert{display:grid;grid-template-columns:110px 1fr auto;gap:14px;padding:14px 0;
border-top:1px solid var(--line);align-items:center;animation:in .4s ease}
@keyframes in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.badge{display:inline-block;padding:4px 10px;border-radius:8px;font-size:12px;font-weight:700;
color:#0b1020;background:var(--c)}
.route{font-family:Consolas,monospace;font-size:14px}
.why{color:var(--muted);font-size:13px;margin-top:4px}
.meta{text-align:right;color:var(--muted);font-size:12px}
.sev{font-weight:700;font-size:11px;letter-spacing:.6px}
.empty{color:var(--muted);text-align:center;padding:40px 0}
@media(max-width:640px){.alert{grid-template-columns:1fr}.meta{text-align:left}}
</style></head><body><div class="wrap">
<header>
  <div><h1>Network Intrusion Detection System</h1>
  <div class="sub">Real-time hybrid detection: rule engine + machine learning</div></div>
  <div class="status"><span class="dot" id="dot"></span><span id="st">Live</span></div>
</header>

<div class="cards">
  <div class="card" style="--c:#7aa2ff"><div class="l">Total alerts</div><div class="n" id="total">0</div></div>
  <div class="card" style="--c:var(--dos)"><div class="l">DoS / SYN flood</div><div class="n" id="dos">0</div></div>
  <div class="card" style="--c:var(--brute)"><div class="l">Brute force</div><div class="n" id="brute">0</div></div>
  <div class="card" style="--c:var(--scan)"><div class="l">Port scan</div><div class="n" id="scan">0</div></div>
</div>

<div class="panel"><h2>Alerts per minute (last 15 min)</h2>
  <div class="bars" id="bars"></div>
  <div class="axis"><span>15 min ago</span><span>now</span></div></div>

<div class="panel"><h2>Live alert feed</h2>
  <div class="chips" id="chips"></div>
  <div id="feed"></div></div>
</div>

<script>
const META={
 dos:{name:"DoS / SYN Flood",color:"#ff5c7a",sev:"CRITICAL",why:"One source is flooding the target with connection requests to exhaust it."},
 brute:{name:"Brute Force",color:"#ffb020",sev:"HIGH",why:"Repeated connection attempts to a login service, likely password guessing."},
 scan:{name:"Port Scan",color:"#4cc9f0",sev:"MEDIUM",why:"One host is probing many ports to find open services (reconnaissance)."},
 ml:{name:"ML Detected",color:"#a78bfa",sev:"HIGH",why:"The ML model classified this traffic flow as malicious."}
};
const kind=t=>t.startsWith("DoS")?"dos":t.startsWith("Brute")?"brute":t.startsWith("Port")?"scan":"ml";
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let filter="all",data={alerts:[],counts:{},total:0};

function drawChips(){
  const items=[["all","All"],["dos","DoS"],["brute","Brute force"],["scan","Port scan"]];
  document.getElementById("chips").innerHTML=items.map(([k,l])=>
    `<span class="chip ${filter===k?"on":""}" onclick="setFilter('${k}')">${l}</span>`).join("");
}
function setFilter(k){filter=k;drawChips();drawFeed();}

function drawBars(){
  const N=15,now=Date.now(),b=Array.from({length:N},()=>({}));
  data.alerts.forEach(a=>{
    const m=Math.floor((now-new Date(a.time.replace(" ","T")).getTime())/60000);
    if(m>=0&&m<N){const k=kind(a.type);b[N-1-m][k]=(b[N-1-m][k]||0)+1;}
  });
  const tot=x=>Object.values(x).reduce((s,v)=>s+v,0);
  const max=Math.max(1,...b.map(tot));
  document.getElementById("bars").innerHTML=b.map(x=>
    `<div class="col">`+Object.keys(x).map(k=>
      `<div class="seg" style="height:${x[k]/max*100}%;background:${META[k].color}"></div>`).join("")+`</div>`).join("");
}

function drawFeed(){
  const list=data.alerts.filter(a=>filter==="all"||kind(a.type)===filter).slice(0,40);
  document.getElementById("feed").innerHTML=list.length?list.map(a=>{
    const m=META[kind(a.type)];
    return `<div class="alert">
      <div><span class="badge" style="--c:${m.color}">${m.name}</span></div>
      <div><div class="route">${esc(a.src)} &rarr; ${a.dst==="-"?"this host (multiple ports)":esc(a.dst)}${a.dport&&a.dport!=="-"?":"+esc(a.dport):""}</div>
        <div class="why">${esc(a.detail)} &middot; ${m.why}</div></div>
      <div class="meta"><div class="sev" style="color:${m.color}">${m.sev}</div>${esc(a.time)}</div></div>`;
  }).join(""):`<div class="empty">No alerts yet. The network looks quiet.</div>`;
}

async function refresh(){
  try{
    const r=await fetch("/api/alerts");data=await r.json();
    document.getElementById("total").textContent=data.total;
    document.getElementById("dos").textContent=data.counts["DoS/SYN Flood"]||0;
    document.getElementById("brute").textContent=data.counts["BruteForce"]||0;
    document.getElementById("scan").textContent=data.counts["PortScan"]||0;
    document.getElementById("dot").className="dot";
    document.getElementById("st").textContent="Live";
    drawBars();drawFeed();
  }catch(e){
    document.getElementById("dot").className="dot off";
    document.getElementById("st").textContent="Offline";
  }
}
drawChips();refresh();setInterval(refresh,2000);
</script></body></html>"""

@app.route("/")
def index():
    return PAGE

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)