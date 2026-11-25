import { useState, useEffect } from 'react';
import { severity, sevColor } from '../utils';
import { useAuth } from '../AuthContext';
import { analyticsApi, downloadReport } from '../api';
import { CountUp, Skeleton, ErrorBox, Empty, SeverityBadge } from '../ui';

const RANGES = [
  [1, 'Last hour'],
  [6, 'Last 6 hours'],
  [24, 'Last 24 hours'],
  [168, 'Last 7 days'],
  [720, 'Last 30 days'],
];

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
  const r = 68, c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <svg viewBox="0 0 190 190" style={{ width: 176, height: 176, flexShrink: 0 }}>
      <circle cx="95" cy="95" r={r} fill="none" stroke="var(--surface-2)" strokeWidth="24" />
      {data.map((d) => {
        const len = (d.n / total) * c;
        const el = (
          <circle
            key={d.label}
            cx="95"
            cy="95"
            r={r}
            fill="none"
            stroke={d.color}
            strokeWidth="24"
            strokeDasharray={`${len} ${c - len}`}
            strokeDashoffset={-offset}
            transform="rotate(-90 95 95)"
          >
            <title>{`${d.label}: ${d.n} (${((d.n / total) * 100).toFixed(1)}%)`}</title>
          </circle>
        );
        offset += len;
        return el;
      })}
      <text x="95" y="91" textAnchor="middle" fill="var(--text)" fontSize="26" fontWeight="700" className="mono">
        {data.length ? total : 0}
      </text>
      <text x="95" y="111" textAnchor="middle" fill="var(--muted)" fontSize="11">
        alerts
      </text>
    </svg>
  );
}

function BarList({ rows, color = 'var(--accent)', prefix = '' }) {
  const max = Math.max(1, ...rows.map(([, n]) => n));
  const sum = rows.reduce((s, [, n]) => s + n, 0) || 1;
  if (!rows.length) {
    return <Empty title="No data in this window" note="Select a wider time range above." />;
  }
  return (
    <div className="an-barlist">
      {rows.map(([name, n]) => {
        const pct = Math.round((n / sum) * 100);
        return (
          <div key={name} className="an-bar-item">
            <div className="an-bar-top">
              <span className="mono an-bar-name">{prefix}{name}</span>
              <span className="mono an-bar-count">
                <b>{n.toLocaleString()}</b> <small>({pct}%)</small>
              </span>
            </div>
            <div className="an-bar-track">
              <div
                className="an-bar-fill"
                style={{ width: `${(n / max) * 100}%`, background: color }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function Analytics() {
  const { token } = useAuth();
  const [hours, setHours] = useState(() => Number(sessionStorage.getItem('an_hours')) || 24);
  const { data, error } = useSummary(hours);
  const [busy, setBusy] = useState(false);
  const [dlError, setDlError] = useState('');
  const [hoverIdx, setHoverIdx] = useState(null);

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
    <div className="an-header">
      <div>
        <h2>Security Analytics</h2>
        <p className="band-sub">
          Historical traffic volume, severity distribution, top offending sources, and targeted service ports.
        </p>
      </div>
      <div className="an-controls">
        <div className="an-range-pills" role="group" aria-label="Time range">
          {RANGES.map(([h, l]) => (
            <button
              key={h}
              type="button"
              className={'an-pill' + (hours === h ? ' active' : '')}
              onClick={() => pickRange(h)}
            >
              {l}
            </button>
          ))}
        </div>
        <button className="btn sm" onClick={onDownload} disabled={busy}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
            <polyline points="7 10 12 15 17 10" />
            <line x1="12" y1="15" x2="12" y2="3" />
          </svg>
          <span>{busy ? 'Generating PDF...' : 'Download PDF Report'}</span>
        </button>
      </div>
      {dlError && <div style={{ color: 'var(--danger)', fontSize: 12, width: '100%' }}>{dlError}</div>}
    </div>
  );

  if (error) return <div style={{ display: 'grid', gap: 16 }}>{header}<ErrorBox message={error} /></div>;
  if (!data) {
    return (
      <div style={{ display: 'grid', gap: 16 }}>
        {header}
        <div className="grid">
          {[0, 1, 2, 3].map((i) => <Skeleton key={i} h={104} r={16} />)}
        </div>
        <Skeleton h={250} r={16} />
        <div className="dash-trend-grid">
          <Skeleton h={240} r={16} />
          <Skeleton h={240} r={16} />
        </div>
      </div>
    );
  }

  const types = Object.entries(data.by_type).sort((a, b) => b[1] - a[1]);
  const sevMap = {};
  types.forEach(([t, n]) => { const s = severity(t); sevMap[s] = (sevMap[s] || 0) + n; });
  const sevData = Object.entries(sevMap).map(([label, n]) => ({ label, n, color: sevColor[label] }));

  const bars = data.timeline.map((b) => ({ label: tlLabel(b.hour, data.bucket), n: b.count }));
  const maxBar = Math.max(1, ...bars.map((b) => b.n));
  const W = 680, H = 180;
  const pts = bars.map((b, i) => [
    (i / Math.max(1, bars.length - 1)) * (W - 24) + 12,
    H - (b.n / maxBar) * (H - 32) - 14,
  ]);
  const line = pts.map((p) => p.join(',')).join(' ');
  const area = pts.length ? `${pts[0][0]},${H} ${line} ${pts[pts.length - 1][0]},${H}` : '';

  return (
    <div style={{ display: 'grid', gap: 18 }}>
      {header}

      <div className="grid">
        <div className="card kpi-card">
          <div className="stat-label">Total Alerts</div>
          <div className="stat-value"><CountUp value={data.total} /></div>
          <div className="kpi-sub mono">In selected {hours}h window</div>
        </div>
        <div className="card kpi-card">
          <div className="stat-label">Attack Signatures</div>
          <div className="stat-value"><CountUp value={types.length} /></div>
          <div className="kpi-sub mono">Distinct classes triggered</div>
        </div>
        <div className="card kpi-card">
          <div className="stat-label">Unique Sources</div>
          <div className="stat-value" style={{ color: 'var(--danger)' }}><CountUp value={data.unique_sources} /></div>
          <div className="kpi-sub mono">Offending source IPs</div>
        </div>
        <div className="card kpi-card">
          <div className="stat-label">Unique Targets</div>
          <div className="stat-value" style={{ color: 'var(--warn)' }}><CountUp value={data.unique_targets} /></div>
          <div className="kpi-sub mono">Destination hosts probed</div>
        </div>
      </div>

      <div className="card">
        <div className="band-head">
          <div>
            <div className="stat-label">Alerts over time · selected range (per {data.bucket})</div>
            <p className="band-sub">Hover over any interval along the curve to inspect exact historical volume.</p>
          </div>
          {hoverIdx !== null && bars[hoverIdx] ? (
            <span className="badge mono" style={{ color: 'var(--accent)', borderColor: 'var(--accent-border)' }}>
              {bars[hoverIdx].label} · {bars[hoverIdx].n} alerts
            </span>
          ) : (
            <span className="badge mono">Peak: {maxBar} / {data.bucket}</span>
          )}
        </div>

        {bars.length ? (
          <>
            <svg
              viewBox={`0 0 ${W} ${H}`}
              style={{ width: '100%', height: 195, overflow: 'visible' }}
              onMouseLeave={() => setHoverIdx(null)}
            >
              <defs>
                <linearGradient id="ar" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0" stopColor="var(--accent)" stopOpacity=".32" />
                  <stop offset="1" stopColor="var(--accent)" stopOpacity="0" />
                </linearGradient>
              </defs>
              {[0.25, 0.5, 0.75].map((g) => (
                <line
                  key={g}
                  x1="12"
                  x2={W - 12}
                  y1={H * g}
                  y2={H * g}
                  stroke="var(--divider)"
                  strokeDasharray="4 4"
                  strokeWidth="1"
                />
              ))}
              <polygon points={area} fill="url(#ar)" />
              <polyline
                points={line}
                fill="none"
                stroke="var(--accent)"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              {pts.map(([x, y], i) => (
                <g key={i} onMouseEnter={() => setHoverIdx(i)} style={{ cursor: 'pointer' }}>
                  <rect x={x - 10} y="0" width="20" height={H} fill="transparent" />
                  <circle
                    cx={x}
                    cy={y}
                    r={hoverIdx === i ? 5.5 : 2.8}
                    fill={hoverIdx === i ? 'var(--accent)' : 'var(--surface)'}
                    stroke="var(--accent)"
                    strokeWidth="2"
                  />
                </g>
              ))}
            </svg>
            <div className="mono" style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--muted)', fontSize: 11, marginTop: 6 }}>
              <span>{bars[0].label}</span>
              <span>{bars[Math.floor(bars.length / 2)]?.label}</span>
              <span>{bars[bars.length - 1].label}</span>
            </div>
          </>
        ) : (
          <Empty title="No alerts in this range" note="Try selecting Last 7 days or Last 30 days above." />
        )}
      </div>

      <div className="grid an-two-col">
        <div className="card">
          <div className="stat-label" style={{ marginBottom: 14 }}>Severity history · selected range</div>
          {sevData.length === 0 ? (
            <Empty title="No severity data" note="No alerts recorded in this time window." />
          ) : (
            <div className="an-donut-wrap" style={{ display: 'flex', alignItems: 'center', gap: 24, flexWrap: 'wrap' }}>
              <Donut data={sevData} />
              <div style={{ flex: 1, minWidth: 160, display: 'grid', gap: 10 }}>
                {sevData.map((d) => {
                  const pct = Math.round((d.n / Math.max(1, data.total)) * 100);
                  return (
                    <div key={d.label} className="an-sev-row">
                      <SeverityBadge level={d.label} />
                      <span className="mono" style={{ marginLeft: 'auto' }}>{d.n.toLocaleString()}</span>
                      <span className="mono" style={{ color: 'var(--muted)', fontSize: 12, minWidth: 38, textAlign: 'right' }}>
                        {pct}%
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="stat-label" style={{ marginBottom: 14 }}>Attack signatures history · selected range</div>
          <BarList rows={types} color="var(--accent)" />
        </div>
      </div>

      <div className="grid an-two-col">
        <div className="card">
          <div className="stat-label" style={{ marginBottom: 14 }}>Top attacker IPs · selected range</div>
          <BarList rows={data.sources} color="var(--accent)" />
        </div>
        <div className="card">
          <div className="stat-label" style={{ marginBottom: 14 }}>Targeted ports · selected range</div>
          <BarList rows={data.top_ports} color="var(--accent)" prefix="Port " />
        </div>
      </div>
    </div>
  );
}
