import { usePolling, severity, sevColor } from '../utils';

function perMinute(alerts, span = 30) {
  const ts = alerts
    .map((a) => Math.floor(Date.parse(a.time.replace(' ', 'T') + 'Z') / 60000))
    .filter((n) => !isNaN(n));
  if (!ts.length) return [];
  const end = Math.max(...ts);
  const out = [];
  for (let m = end - span + 1; m <= end; m++) {
    out.push({ label: new Date(m * 60000).toISOString().slice(11, 16), n: ts.filter((x) => x === m).length });
  }
  return out;
}

function top(items, n = 5) {
  const map = {};
  items.forEach((x) => { if (x && x !== '-') map[x] = (map[x] || 0) + 1; });
  return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, n);
}

function Donut({ data }) {
  const total = data.reduce((s, d) => s + d.n, 0) || 1;
  const r = 70, c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <svg viewBox="0 0 200 200" style={{ width: 200, height: 200 }}>
      <circle cx="100" cy="100" r={r} fill="none" stroke="rgba(255,255,255,.06)" strokeWidth="26" />
      {data.map((d) => {
        const len = (d.n / total) * c;
        const el = (
          <circle key={d.label} cx="100" cy="100" r={r} fill="none" stroke={d.color} strokeWidth="26"
            strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-offset}
            transform="rotate(-90 100 100)" />
        );
        offset += len;
        return el;
      })}
      <text x="100" y="98" textAnchor="middle" fill="#e6eaf5" fontSize="28" fontWeight="700">{total === 1 && !data.length ? 0 : total}</text>
      <text x="100" y="118" textAnchor="middle" fill="#8b93ad" fontSize="11">alerts</text>
    </svg>
  );
}

function BarList({ rows, color = 'var(--accent)' }) {
  const max = Math.max(1, ...rows.map(([, n]) => n));
  if (!rows.length) return <p style={{ color: 'var(--muted)' }}>No data yet.</p>;
  return rows.map(([name, n]) => (
    <div key={name} style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 4 }}>
        <span>{name}</span><span style={{ color: 'var(--muted)' }}>{n}</span>
      </div>
      <div style={{ background: 'var(--surface-2)', borderRadius: 6, height: 8 }}>
        <div style={{ width: `${(n / max) * 100}%`, height: '100%', borderRadius: 6, background: color }} />
      </div>
    </div>
  ));
}

export default function Analytics() {
  const stats = usePolling('/stats');
  const recent = usePolling('/?limit=200');

  if (stats.error) return <p style={{ color: 'var(--danger)' }}>{stats.error}</p>;
  if (!stats.data || !recent.data) return <p style={{ color: 'var(--muted)' }}>Loading...</p>;

  const { total, counts, sources } = stats.data;
  const alerts = recent.data.alerts;
  const types = Object.entries(counts).sort((a, b) => b[1] - a[1]);

  const sevMap = {};
  types.forEach(([t, n]) => { const s = severity(t); sevMap[s] = (sevMap[s] || 0) + n; });
  const sevData = Object.entries(sevMap).map(([label, n]) => ({ label, n, color: sevColor[label] }));

  const bars = perMinute(alerts);
  const maxBar = Math.max(1, ...bars.map((b) => b.n));
  const W = 600, H = 160;
  const pts = bars.map((b, i) => [
    (i / Math.max(1, bars.length - 1)) * W,
    H - (b.n / maxBar) * (H - 10) - 5,
  ]);
  const line = pts.map((p) => p.join(',')).join(' ');
  const area = pts.length ? `0,${H} ${line} ${W},${H}` : '';

  const topPorts = top(alerts.map((a) => a.dport));
  const topTargets = top(alerts.map((a) => a.dst));

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <h2>Analytics</h2>

      <div className="grid">
        <div className="card"><div className="stat-label">Total alerts</div><div className="stat-value">{total}</div></div>
        <div className="card"><div className="stat-label">Attack types</div><div className="stat-value">{types.length}</div></div>
        <div className="card"><div className="stat-label">Unique sources</div><div className="stat-value">{sources.length}</div></div>
        <div className="card"><div className="stat-label">Unique targets</div><div className="stat-value">{topTargets.length ? new Set(alerts.map((a) => a.dst)).size : 0}</div></div>
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 12 }}>Alert activity (last 30 minutes of activity)</div>
        {bars.length ? (
          <>
            <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 180 }} preserveAspectRatio="none">
              <defs>
                <linearGradient id="ar" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0" stopColor="#22d3ee" stopOpacity=".45" />
                  <stop offset="1" stopColor="#8b5cf6" stopOpacity="0" />
                </linearGradient>
              </defs>
              <polygon points={area} fill="url(#ar)" />
              <polyline points={line} fill="none" stroke="#22d3ee" strokeWidth="2.5" vectorEffect="non-scaling-stroke" />
            </svg>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--muted)', fontSize: 11 }}>
              <span>{bars[0].label}</span><span>{bars[bars.length - 1].label}</span>
            </div>
          </>
        ) : <p style={{ color: 'var(--muted)' }}>No data yet.</p>}
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
        <div className="card">
          <div className="stat-label" style={{ marginBottom: 12 }}>Severity breakdown</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 24, flexWrap: 'wrap' }}>
            <Donut data={sevData} />
            <div>
              {sevData.map((d) => (
                <div key={d.label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, fontSize: 14 }}>
                  <span style={{ width: 12, height: 12, borderRadius: 3, background: d.color }} />
                  {d.label} <span style={{ color: 'var(--muted)' }}>({d.n})</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="stat-label" style={{ marginBottom: 12 }}>Attack types</div>
          <BarList rows={types} color="linear-gradient(90deg, var(--accent), var(--accent-2))" />
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
        <div className="card">
          <div className="stat-label" style={{ marginBottom: 12 }}>Top attacker sources</div>
          <BarList rows={sources.slice(0, 5)} color="var(--danger)" />
        </div>
        <div className="card">
          <div className="stat-label" style={{ marginBottom: 12 }}>Most targeted ports</div>
          <BarList rows={topPorts} color="var(--accent-2)" />
        </div>
      </div>
    </div>
  );
}