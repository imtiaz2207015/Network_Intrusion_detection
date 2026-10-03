import { Link } from 'react-router-dom';
import { usePolling, severity, sevColor } from '../utils';
import { useAuth } from '../AuthContext';
import { CountUp, Skeleton, ErrorBox, Empty } from '../ui';
import { timeAgo } from '../format';

function buckets(alerts) {
  const ts = alerts
    .map((a) => Math.floor(Date.parse(a.time.replace(' ', 'T') + 'Z') / 60000))
    .filter((n) => !isNaN(n));
  if (!ts.length) return [];
  const end = Math.max(...ts);
  const out = [];
  for (let m = end - 14; m <= end; m++) {
    out.push({ label: new Date(m * 60000).toISOString().slice(11, 16), n: ts.filter((x) => x === m).length });
  }
  return out;
}

function greeting() {
  const h = new Date().getHours();
  return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
}

export default function Dashboard() {
  const { user } = useAuth();
  const stats = usePolling('/stats');
  const recent = usePolling('/?limit=200');

  if (stats.error) return <ErrorBox message={stats.error} />;
  if (!stats.data || !recent.data) {
    return (
      <div style={{ display: 'grid', gap: 16 }}>
        <Skeleton w={280} h={34} />
        <div className="grid">{[0, 1, 2, 3].map((i) => <Skeleton key={i} h={96} r={16} />)}</div>
        <Skeleton h={220} r={16} />
        <Skeleton h={180} r={16} />
      </div>
    );
  }

  const { total, counts, sources } = stats.data;
  const types = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const critical = types.filter(([t]) => severity(t) === 'Critical').reduce((s, [, n]) => s + n, 0);
  const bars = buckets(recent.data.alerts);
  const maxBar = Math.max(1, ...bars.map((b) => b.n));
  const maxType = Math.max(1, ...types.map(([, n]) => n));

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <h2>{greeting()}, {user.username}</h2>
          <p style={{ color: 'var(--muted)', fontSize: 14, marginTop: 4 }}>
            {total ? `${total} alerts recorded so far.` : 'No alerts yet. Your network looks quiet.'}
          </p>
        </div>
        <span className="live"><span className="live-dot" />LIVE</span>
      </div>

      <div className="grid">
        <div className="card"><div className="stat-label">Total alerts</div><div className="stat-value"><CountUp value={total} /></div></div>
        <div className="card"><div className="stat-label">Critical alerts</div><div className="stat-value" style={{ color: 'var(--danger)' }}><CountUp value={critical} /></div></div>
        <div className="card"><div className="stat-label">Top attack type</div><div className="stat-value" style={{ fontSize: 20 }}>{types[0] ? types[0][0] : '-'}</div></div>
        <div className="card"><div className="stat-label">Top source</div><div className="stat-value" style={{ fontSize: 20 }}>{sources[0] ? sources[0][0] : '-'}</div></div>
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 12 }}>Alerts per minute (last 15 minutes of activity)</div>
        {bars.length === 0 ? (
          <Empty title="No activity yet" note="Alerts will appear here as traffic is analysed." />
        ) : (
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 6, height: 150 }}>
            {bars.map((b, i) => (
              <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'flex-end', height: '100%' }}>
                <span style={{ fontSize: 11, color: 'var(--muted)' }}>{b.n || ''}</span>
                <div style={{ width: '100%', height: `${(b.n / maxBar) * 100}%`, minHeight: b.n ? 3 : 0, background: 'linear-gradient(180deg, var(--accent), var(--accent-2))', borderRadius: 4, transition: 'height .5s' }} />
                <span style={{ fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>{b.label}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 12 }}>Attack types</div>
        {types.length === 0 && <Empty title="No attacks detected" note="That's good news." />}
        {types.map(([t, n]) => (
          <div key={t} style={{ marginBottom: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 4 }}>
              <span>{t}</span><span style={{ color: 'var(--muted)' }}>{n}</span>
            </div>
            <div style={{ background: 'var(--surface-2)', borderRadius: 6, height: 8 }}>
              <div style={{ width: `${(n / maxType) * 100}%`, height: '100%', borderRadius: 6, background: sevColor[severity(t)], transition: 'width .6s' }} />
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <div className="stat-label">Latest alerts</div>
          <Link to="/alerts" className="view-all">View all →</Link>
        </div>
        {recent.data.alerts.length === 0 ? (
          <Empty title="No alerts yet" note="New detections will show up here." />
        ) : (
          <table className="table">
            <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th></tr></thead>
            <tbody>
              {recent.data.alerts.slice(0, 5).map((a) => {
                const sev = severity(a.type);
                return (
                  <tr key={a.id}>
                    <td title={a.time} style={{ boxShadow: `inset 3px 0 0 ${sevColor[sev]}` }}>{timeAgo(a.time)}</td>
                    <td><span className="badge" style={{ color: sevColor[sev] }}>{sev}</span></td>
                    <td>{a.type}</td>
                    <td>{a.src}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}