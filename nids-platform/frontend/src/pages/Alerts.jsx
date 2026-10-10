import { useState, useEffect, Fragment } from 'react';
import { usePolling, severity, sevColor, getAdvice } from '../utils';
import { Skeleton, ErrorBox, Empty } from '../ui';
import { timeAgo, downloadCSV } from '../format';
import { useAuth } from '../AuthContext';
import { alertsApi } from '../api';

const PAGE = 20;
const TYPES = ['', 'PortScan', 'BruteForce', 'DoS', 'UDP Flood', 'ICMP Flood'];
const STATUSES = ['new', 'investigating', 'resolved'];

export default function Alerts() {
  const [type, setType] = useState('');
  const [q, setQ] = useState('');
  const [qd, setQd] = useState('');
  const [offset, setOffset] = useState(0);
  const [openId, setOpenId] = useState(null);
  const { token, user } = useAuth();
  const canEdit = !!user && user.role !== 'viewer';
  const [statusF, setStatusF] = useState('');
  const [local, setLocal] = useState({});
  const [msg, setMsg] = useState('');

  async function changeStatus(id, s) {
    try {
      await alertsApi(`/${id}/status`, { method: 'PUT', body: { status: s }, token });
      setLocal((l) => ({ ...l, [id]: s }));
      setMsg('');
    } catch (e) {
      setMsg(e.message);
    }
  }

  useEffect(() => {
    const t = setTimeout(() => { setQd(q); setOffset(0); }, 350);
    return () => clearTimeout(t);
  }, [q]);

  const path = `/?limit=${PAGE}&offset=${offset}&type=${encodeURIComponent(type)}&q=${encodeURIComponent(qd)}&status=${statusF}`;
  const { data, error } = usePolling(path);
  const total = data ? data.total : 0;
  const filtered = type || q || statusF;

  function clearFilters() { setType(''); setQ(''); setQd(''); setStatusF(''); setOffset(0); }

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
        <select className="input" style={{ width: 170 }} value={statusF}
          onChange={(e) => { setStatusF(e.target.value); setOffset(0); }}>
          <option value="">All statuses</option>
          <option value="new">New</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
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
              <tr><th>Time</th><th>Severity</th><th>Type</th><th>Status</th><th>Source</th><th>Destination</th><th>Details</th></tr>
            </thead>
            <tbody>
              {data.alerts.map((a) => {
                const sev = severity(a.type);
                const adv = getAdvice(a.type);
                const isOpen = openId === a.id;
                const st = local[a.id] ?? a.status;
                const stColor = st === 'resolved' ? '#22c55e' : st === 'investigating' ? 'var(--warn)' : 'var(--muted)';
                return (
                  <Fragment key={a.id}>
                    <tr onClick={() => setOpenId(isOpen ? null : a.id)} style={{ cursor: 'pointer' }}>
                      <td title={a.time} style={{ boxShadow: `inset 3px 0 0 ${sevColor[sev]}`, whiteSpace: 'nowrap' }}>{timeAgo(a.time)}</td>
                      <td><span className="badge" style={{ color: sevColor[sev] }}>{sev}</span></td>
                      <td>{a.type}</td>
                      <td><span className="badge" style={{ color: stColor }}>{st}</span></td>
                      <td>{a.src}</td>
                      <td>{a.dst}{a.dport && a.dport !== '-' ? ':' + a.dport : ''}</td>
                      <td style={{ color: 'var(--muted)' }}>{a.detail}</td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={7} style={{ background: 'var(--surface-2)', whiteSpace: 'normal' }}>
                          <div style={{ padding: '8px 4px', display: 'grid', gap: 8, fontSize: 14 }}>
                            <div><b>What happened:</b> {adv.what}</div>
                            <div><b>Why it matters:</b> {adv.risk}</div>
                            <div>
                              <b>Recommended actions:</b>
                              <ul style={{ margin: '6px 0 0 18px' }}>
                                {adv.actions.map((x) => <li key={x}>{x}</li>)}
                              </ul>
                            </div>
                            {canEdit ? (
                              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                                <b>Status:</b>
                                {STATUSES.map((s) => (
                                  <button key={s} className="btn ghost sm" disabled={st === s}
                                    onClick={() => changeStatus(a.id, s)}>{s}</button>
                                ))}
                                {msg && <span style={{ color: 'var(--danger)', fontSize: 12 }}>{msg}</span>}
                              </div>
                            ) : (
                              <div style={{ color: 'var(--muted)', fontSize: 12 }}>Only admins and analysts can change status.</div>
                            )}
                            <div style={{ color: 'var(--muted)', fontSize: 12 }}>
                              Source {a.src} - {a.time} - alert #{a.id}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
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