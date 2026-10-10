import { useState, useEffect } from 'react';
import { severity, sevColor } from '../utils';
import { useAuth } from '../AuthContext';
import { analyticsApi, downloadReport } from '../api';

const RANGES = [[1, 'Last hour'], [6, 'Last 6 hours'], [24, 'Last 24 hours'], [168, 'Last 7 days'], [720, 'Last 30 days']];

function useSummary(hours) {
  const { token, logout } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  useEffect(() => {
    let alive = true;
    setData(null);
    async function load() {
      try {
        const d = await analyticsApi(`/summary?hours=${hours}`, { token });
        if (alive) { setData(d); setError(''); }
      } catch (e) {
        if (e.status === 401) logout();
        else if (alive) setError(e.message);
      }
    }
    load();
    const id = setInterval(load, 5000);
    return () => { alive = false; clearInterval(id); };
  }, [hours, token]);
  return { data, error };
}

function tlLabel(key, bucket) {
  if (bucket === 'minute') return key.slice(11);
  if (bucket === 'hour') return key.slice(11) + ':00';
  return key.slice(5);
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
      <text x="100" y="98" textAnchor="middle" fill="#e6eaf5" fontSize="28" fontWeight="700">{data.length ? total : 0}</text>
      <text x="100" y="118" textAnchor="middle" fill="#8b93ad" fontSize="11">alerts</text>
    </svg>
  );
}

function BarList({ rows, color = 'var(--accent)' }) {
  const max = Math.max(1, ...rows.map(([, n]) => n));
  if (!rows.length) return <p style={{ color: 'var(--muted)' }}>No data in this range.</p>;
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
  const { token } = useAuth();
  const [hours, setHours] = useState(() => Number(sessionStorage.getItem('an_hours')) || 24);
  const { data, error } = useSummary(hours);
  const [busy, setBusy] = useState(false);
  const [dlError, setDlError] = useState('');

  function pickRange(h) {
    setHours(h);
    sessionStorage.setItem('an_hours', String(h));
  }

  async function onDownload() {
    setBusy(true);
    setDlError('');
    try {
      await downloadReport(token, hours);
    } catch (e) {
      setDlError(e.message);
    }
    setBusy(false);
  }

  const header = (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
      <h2>Analytics</h2>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <select className="input" style={{ width: 170 }} value={hours}
          onChange={(e) => pickRange(Number(e.target.value))}>
          {RANGES.map(([h, l]) => <option key={h} value={h}>{l}</option>)}
        </select>
        <button onClick={onDownload} disabled={busy}
          style={{ padding: '10px 18px', borderRadius: 8, border: 'none', cursor: 'pointer', fontWeight: 600,
                   color: '#06101f', background: 'linear-gradient(90deg, var(--accent), var(--accent-2))' }}>
          {busy ? 'Generating...' : 'Download PDF report'}
        </button>
      </div>
      {dlError && <div style={{ color: 'var(--danger)', fontSize: 12, width: '100%' }}>{dlError}</div>}
    </div>
  );

  if (error) return <div style={{ display: 'grid', gap: 16 }}>{header}<p style={{ color: 'var(--danger)' }}>{error}</p></div>;
  if (!data) return <div style={{ display: 'grid', gap: 16 }}>{header}<p style={{ color: 'var(--muted)' }}>Loading...</p></div>;

  const types = Object.entries(data.by_type).sort((a, b) => b[1] - a[1]);
  const sevMap = {};
  types.forEach(([t, n]) => { const s = severity(t); sevMap[s] = (sevMap[s] || 0) + n; });
  const sevData = Object.entries(sevMap).map(([label, n]) => ({ label, n, color: sevColor[label] }));

  const bars = data.timeline.map((b) => ({ label: tlLabel(b.hour, data.bucket), n: b.count }));
  const maxBar = Math.max(1, ...bars.map((b) => b.n));
  const W = 600, H = 160;
  const pts = bars.map((b, i) => [
    (i / Math.max(1, bars.length - 1)) * W,
    H - (b.n / maxBar) * (H - 10) - 5,
  ]);
  const line = pts.map((p) => p.join(',')).join(' ');
  const area = pts.length ? `0,${H} ${line} ${W},${H}` : '';

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      {header}

      <div className="grid">
        <div className="card"><div className="stat-label">Total alerts</div><div className="stat-value">{data.total}</div></div>
        <div className="card"><div className="stat-label">Attack types</div><div className="stat-value">{types.length}</div></div>
        <div className="card"><div className="stat-label">Unique sources</div><div className="stat-value">{data.unique_sources}</div></div>
        <div className="card"><div className="stat-label">Unique targets</div><div className="stat-value">{data.unique_targets}</div></div>
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 12 }}>Alert activity (per {data.bucket})</div>
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
        ) : <p style={{ color: 'var(--muted)' }}>No alerts in this range.</p>}
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
          <BarList rows={data.sources} color="var(--danger)" />
        </div>
        <div className="card">
          <div className="stat-label" style={{ marginBottom: 12 }}>Most targeted ports</div>
          <BarList rows={data.top_ports} color="var(--accent-2)" />
        </div>
      </div>
    </div>
  );
}