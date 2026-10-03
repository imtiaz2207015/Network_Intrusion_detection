import { useState, useEffect } from 'react';
import { usePolling, severity, sevColor } from '../utils';
import { Skeleton, ErrorBox, Empty } from '../ui';
import { timeAgo, downloadCSV } from '../format';

const PAGE = 20;
const TYPES = ['', 'PortScan', 'BruteForce', 'DoS', 'UDP Flood', 'ICMP Flood'];

export default function Alerts() {
  const [type, setType] = useState('');
  const [q, setQ] = useState('');
  const [qd, setQd] = useState('');
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => { setQd(q); setOffset(0); }, 350);
    return () => clearTimeout(t);
  }, [q]);

  const path = `/?limit=${PAGE}&offset=${offset}&type=${encodeURIComponent(type)}&q=${encodeURIComponent(qd)}`;
  const { data, error } = usePolling(path);
  const total = data ? data.total : 0;
  const filtered = type || q;

  function clearFilters() { setType(''); setQ(''); setQd(''); setOffset(0); }

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <h2>Alerts</h2>
        <button className="btn ghost sm" disabled={!data || !data.alerts.length}
          onClick={() => downloadCSV(data.alerts)}>⬇ Export CSV</button>
      </div>

      <div className="card" style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <select className="input" style={{ width: 200 }} value={type}
          onChange={(e) => { setType(e.target.value); setOffset(0); }}>
          {TYPES.map((t) => <option key={t} value={t}>{t || 'All types'}</option>)}
        </select>
        <input className="input" style={{ flex: 1, minWidth: 200 }} placeholder="Search source, destination, details..."
          value={q} onChange={(e) => setQ(e.target.value)} />
        {filtered && <button className="btn ghost sm" onClick={clearFilters}>✕ Clear</button>}
      </div>

      {error && <ErrorBox message={error} />}

      <div className="card" style={{ overflowX: 'auto' }}>
        {!data ? (
          <div style={{ display: 'grid', gap: 10 }}>
            {[0, 1, 2, 3, 4, 5].map((i) => <Skeleton key={i} h={38} />)}
          </div>
        ) : data.alerts.length === 0 ? (
          <Empty icon="🔍" title="No alerts found"
            note={filtered ? 'Try different filters or clear them.' : 'No detections yet.'} />
        ) : (
          <table className="table">
            <thead>
              <tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th><th>Destination</th><th>Details</th></tr>
            </thead>
            <tbody>
              {data.alerts.map((a) => {
                const sev = severity(a.type);
                return (
                  <tr key={a.id}>
                    <td title={a.time} style={{ boxShadow: `inset 3px 0 0 ${sevColor[sev]}`, whiteSpace: 'nowrap' }}>{timeAgo(a.time)}</td>
                    <td><span className="badge" style={{ color: sevColor[sev] }}>{sev}</span></td>
                    <td>{a.type}</td>
                    <td>{a.src}</td>
                    <td>{a.dst}{a.dport && a.dport !== '-' ? ':' + a.dport : ''}</td>
                    <td style={{ color: 'var(--muted)' }}>{a.detail}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14, gap: 8, flexWrap: 'wrap' }}>
          <span style={{ color: 'var(--muted)', fontSize: 13 }}>
            {total ? `${offset + 1}-${Math.min(offset + PAGE, total)} of ${total}` : '0 results'}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn ghost sm" disabled={offset === 0} onClick={() => setOffset(offset - PAGE)}>← Previous</button>
            <button className="btn ghost sm" disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>Next →</button>
          </div>
        </div>
      </div>
    </div>
  );
}