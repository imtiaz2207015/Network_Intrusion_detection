import { useState, useEffect, useRef, useMemo, Fragment } from 'react';
import { Link } from 'react-router-dom';
import { usePolling, severity, sevColor, getAdvice } from '../utils';
import { Skeleton, ErrorBox } from '../ui';
import { formatTimestamp, formatAbsoluteTime, downloadCSV } from '../format';
import { useAuth } from '../AuthContext';
import { alertsApi } from '../api';
import {
  useBlockedIps,
  BlockIpModal,
  BlockedIpChip,
} from '../BlockedIps';

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
  const [sevF, setSevF] = useState('');
  const [local, setLocal] = useState({});
  const [msg, setMsg] = useState('');
  const [freshIds, setFreshIds] = useState(new Set());
  const [blockTarget, setBlockTarget] = useState(null);
  const [blockToastIp, setBlockToastIp] = useState('');
  const [isMobile480, setIsMobile480] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(max-width: 480px)').matches
  );
  const seenRef = useRef(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(max-width: 480px)');
    const onChange = (e) => setIsMobile480(e.matches);
    setIsMobile480(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  const blockedState = useBlockedIps();
  const { activeMap, activeList, addOptimisticBlock, unblockIp } = blockedState;

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
  const filtered = Boolean(type || q || statusF || sevF);

  useEffect(() => {
    const list = data?.alerts;
    if (!list) return;
    if (seenRef.current === null) {
      seenRef.current = new Set(list.map((a) => a.id));
      return;
    }
    const arrived = list.filter((a) => !seenRef.current.has(a.id));
    if (!arrived.length) return;
    arrived.forEach((a) => seenRef.current.add(a.id));
    setFreshIds(new Set(arrived.map((a) => a.id)));
    const timer = setTimeout(() => setFreshIds(new Set()), 2200);
    return () => clearTimeout(timer);
  }, [data]);

  const loadedAlerts = data?.alerts || [];

  const sevCounts = useMemo(() => {
    const c = { All: loadedAlerts.length, Critical: 0, High: 0, Medium: 0 };
    for (const a of loadedAlerts) {
      const s = severity(a.type);
      if (c[s] !== undefined) c[s] += 1;
    }
    return c;
  }, [loadedAlerts]);

  const visibleAlerts = useMemo(() => {
    if (!sevF) return loadedAlerts;
    return loadedAlerts.filter((a) => severity(a.type) === sevF);
  }, [loadedAlerts, sevF]);

  function clearFilters() {
    setType('');
    setQ('');
    setQd('');
    setStatusF('');
    setSevF('');
    setOffset(0);
  }

  function renderBlockAction(a) {
    if (!a.src || a.src === '-') return null;
    const activeBlock = activeMap.get(a.src);
    if (activeBlock) {
      return (
        <button
          type="button"
          className="btn ghost sm blk-unblock-btn"
          aria-label={`Unblock IP ${a.src}`}
          onClick={(e) => {
            e.stopPropagation();
            unblockIp(activeBlock);
          }}
        >
          Unblock
        </button>
      );
    }
    return (
      <button
        type="button"
        className="btn ghost sm blk-trigger-btn"
        aria-label={`Block IP ${a.src}`}
        onClick={(e) => {
          e.stopPropagation();
          setBlockTarget({ ip: a.src, alertId: a.id });
        }}
      >
        Block IP
      </button>
    );
  }

  const SEV_PILLS = [
    { key: '', label: 'All', count: sevCounts.All, dot: null },
    { key: 'Critical', label: 'Critical', count: sevCounts.Critical, dot: 'var(--danger)' },
    { key: 'High', label: 'High', count: sevCounts.High, dot: 'var(--high)' },
    { key: 'Medium', label: 'Medium', count: sevCounts.Medium, dot: 'var(--warn)' },
  ];

  return (
    <div className="alerts-page">
      {/* Header */}
      <div className="alerts-header">
        <div>
          <h2>Intrusion Alerts</h2>
          <p className="band-sub">
            Inspect live detections, filter by attack signature or workflow status, and block malicious source IPs.
          </p>
        </div>
        <div className="alerts-header-right">
          <span className="badge mono">
            {data ? `${total.toLocaleString()} matching` : 'Syncing...'}
          </span>
          <Link to="/blocked" className="btn ghost sm">
            Blocked IPs ({activeList.length})
          </Link>
          <button
            className="btn ghost sm"
            disabled={!data || !visibleAlerts.length}
            onClick={() => downloadCSV(visibleAlerts)}
          >
            ⬇ Export CSV
          </button>
        </div>
      </div>

      {blockToastIp && (
        <div
          className="help-banner ok"
          role="status"
          style={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap' }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span>✓</span>
            <span>
              Source IP <b className="mono">{blockToastIp}</b> added to the blocklist.{' '}
              <Link to="/blocked" style={{ fontWeight: 700, textDecoration: 'underline' }}>
                View blocked IPs
              </Link>
            </span>
          </div>
          <button
            type="button"
            className="btn ghost sm"
            onClick={() => setBlockToastIp('')}
            aria-label="Dismiss notification"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Sticky Filter Bar */}
      <div className="card alerts-filter-bar">
        <div className="alerts-search-wrap">
          <svg
            className="alerts-search-icon"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            className="input alerts-search-input"
            placeholder={
              isMobile480
                ? 'Search IP, port, attack'
                : 'Search source IP, target IP, port, or signature details...'
            }
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>

        <select
          className="input alerts-select"
          value={type}
          aria-label="Filter by attack type"
          onChange={(e) => { setType(e.target.value); setOffset(0); }}
        >
          {TYPES.map((t) => (
            <option key={t} value={t}>{t || 'All attack types'}</option>
          ))}
        </select>

        <select
          className="input alerts-select"
          value={statusF}
          aria-label="Filter by status"
          onChange={(e) => { setStatusF(e.target.value); setOffset(0); }}
        >
          <option value="">All statuses</option>
          <option value="new">New</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
        </select>

        {filtered && (
          <button className="btn ghost sm" onClick={clearFilters}>
            ✕ Reset filters
          </button>
        )}
      </div>

      {/* Severity Pill Row Above Table */}
      <div className="alerts-sev-row" role="group" aria-label="Filter alerts by severity">
        {SEV_PILLS.map((p) => {
          const active = sevF === p.key;
          return (
            <button
              key={p.label}
              type="button"
              aria-pressed={active}
              className={
                'alerts-sev-pill' +
                (active ? ' active' : '') +
                (p.key ? ' sev-' + p.key.toLowerCase() : '')
              }
              onClick={() => setSevF(active && p.key ? '' : p.key)}
            >
              {p.dot && (
                <span
                  className="alerts-sev-pill-dot"
                  style={{ background: p.dot }}
                  aria-hidden="true"
                />
              )}
              <span>{p.label}</span>
              <span className="mono alerts-sev-pill-count">{p.count}</span>
            </button>
          );
        })}
      </div>

      {error && <ErrorBox message={error} />}

      {/* Alerts Table + Mobile Cards */}
      <div className="card alerts-table-card">
        {!data ? (
          <div style={{ display: 'grid', gap: 10 }}>
            {[0, 1, 2, 3, 4, 5, 6].map((i) => <Skeleton key={i} h={44} r={10} />)}
          </div>
        ) : visibleAlerts.length === 0 ? (
          <div className="alerts-empty">
            <div className="alerts-empty-icon">
              {filtered ? (
                <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  <line x1="8" y1="11" x2="14" y2="11" />
                </svg>
              ) : (
                <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
                  <polyline points="9 12 11 14 15 10" />
                </svg>
              )}
            </div>
            <h3>{filtered ? 'No alerts match your active filters' : 'Network is quiet — no intrusions recorded'}</h3>
            <p>
              {filtered
                ? 'Try broadening your search query, selecting a different severity or attack signature, or resetting the filters.'
                : 'Live packet captures from the sensor will appear here automatically as soon as anomalous flows are detected.'}
            </p>
            {filtered && (
              <button className="btn ghost sm" style={{ marginTop: 12 }} onClick={clearFilters}>
                Reset all filters
              </button>
            )}
          </div>
        ) : (
          <>
            {/* Desktop / Tablet Table */}
            <div className="table-scroll-wrap alerts-desktop-table">
              <table className="table alerts-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Source IP</th>
                    <th>Destination</th>
                    <th>Details</th>
                    <th style={{ width: 92, textAlign: 'right' }} aria-label="Details" />
                  </tr>
                </thead>
                <tbody>
                  {visibleAlerts.map((a) => {
                    const sev = severity(a.type);
                    const adv = getAdvice(a.type);
                    const isOpen = openId === a.id;
                    const isFresh = freshIds.has(a.id);
                    const st = local[a.id] ?? a.status ?? 'new';
                    const activeBlock = activeMap.get(a.src);

                    return (
                      <Fragment key={a.id}>
                        <tr
                          onClick={() => setOpenId(isOpen ? null : a.id)}
                          className={
                            'alerts-row' +
                            (isOpen ? ' is-open' : '') +
                            (isFresh ? ' row-flash' : '')
                          }
                        >
                          <td
                            title={formatAbsoluteTime(a.time)}
                            className="mono"
                            style={{ boxShadow: `inset 3px 0 0 ${sevColor[sev]}`, whiteSpace: 'nowrap' }}
                          >
                            {formatTimestamp(a.time)}
                          </td>
                          <td>
                            <span className={'sev-chip ' + sev.toLowerCase()}>{sev}</span>
                          </td>
                          <td className="alerts-type-cell">{a.type}</td>
                          <td>
                            <span className={'status-pill ' + st}>
                              <i /> {st}
                            </span>
                          </td>
                          <td className="mono alerts-ip-cell">
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                              <span>{a.src}</span>
                              {activeBlock && <BlockedIpChip blockRow={activeBlock} />}
                            </div>
                          </td>
                          <td className="mono alerts-ip-cell">
                            {a.dst}{a.dport && a.dport !== '-' ? ':' + a.dport : ''}
                          </td>
                          <td className="alerts-detail-cell">{a.detail || '—'}</td>
                          <td className="alerts-expand-cell">
                            <span className={'alerts-row-action mono' + (isOpen ? ' open' : '')}>
                              {isOpen ? 'Hide' : 'Details ›'}
                            </span>
                          </td>
                        </tr>

                        {isOpen && (
                          <tr className="alerts-mitigation-row">
                            <td colSpan={8}>
                              <div className="alerts-mitigation-panel">
                                <div className="alerts-mit-grid">
                                  <div className="alerts-mit-box">
                                    <small className="mono">WHAT HAPPENED</small>
                                    <p>{adv.what}</p>
                                  </div>
                                  <div className="alerts-mit-box">
                                    <small className="mono">WHY IT MATTERS</small>
                                    <p>{adv.risk}</p>
                                  </div>
                                </div>

                                <div className="alerts-mit-box">
                                  <small className="mono">RECOMMENDED DEFENSIVE ACTIONS</small>
                                  <ul className="alerts-mit-list">
                                    {adv.actions.map((x) => <li key={x}>{x}</li>)}
                                  </ul>
                                </div>

                                <div className="alerts-mit-footer">
                                  <div className="alerts-status-controls">
                                    {renderBlockAction(a)}
                                    {canEdit && (
                                      <>
                                        <span className="mono alerts-status-label" style={{ marginLeft: 6 }}>
                                          STATUS:
                                        </span>
                                        {STATUSES.map((s) => (
                                          <button
                                            key={s}
                                            type="button"
                                            className={'status-btn ' + s + (st === s ? ' active' : '')}
                                            disabled={st === s}
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              changeStatus(a.id, s);
                                            }}
                                          >
                                            {s}
                                          </button>
                                        ))}
                                        {msg && <span style={{ color: 'var(--danger)', fontSize: 12 }}>{msg}</span>}
                                      </>
                                    )}
                                  </div>

                                  <div className="alerts-mit-meta mono">
                                    <Link to="/assistant" onClick={(e) => e.stopPropagation()}>
                                      Deep AI Explain →
                                    </Link>
                                  </div>
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
            </div>

            {/* Mobile Alert Cards (<= 640px / 360px width) */}
            <div className="alerts-mobile-list">
              {visibleAlerts.map((a) => {
                const sev = severity(a.type);
                const adv = getAdvice(a.type);
                const isOpen = openId === a.id;
                const isFresh = freshIds.has(a.id);
                const st = local[a.id] ?? a.status ?? 'new';

                return (
                  <div
                    key={a.id}
                    className={
                      'alerts-mcard' +
                      (isOpen ? ' is-open' : '') +
                      (isFresh ? ' row-flash' : '')
                    }
                    style={{ borderLeft: `3px solid ${sevColor[sev]}` }}
                  >
                    <div
                      className="alerts-mcard-top"
                      onClick={() => setOpenId(isOpen ? null : a.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span className={'sev-chip ' + sev.toLowerCase()}>{sev}</span>
                        <strong style={{ fontSize: 14 }}>{a.type}</strong>
                        <span className={'status-pill ' + st}>
                          <i /> {st}
                        </span>
                      </div>
                      <span
                        className="mono"
                        title={formatAbsoluteTime(a.time)}
                        style={{ fontSize: 11.5, color: 'var(--muted)' }}
                      >
                        {formatTimestamp(a.time)}
                      </span>
                    </div>

                    <div className="alerts-mcard-ips mono">
                      <span>Src: <b>{a.src}</b></span>
                      {activeMap.get(a.src) && <BlockedIpChip blockRow={activeMap.get(a.src)} />}
                      <span>→</span>
                      <span>
                        Dst: {a.dst}{a.dport && a.dport !== '-' ? ':' + a.dport : ''}
                      </span>
                    </div>

                    {a.detail && (
                      <div className="alerts-mcard-detail">{a.detail}</div>
                    )}

                    <div className="alerts-mcard-actions">
                      {renderBlockAction(a)}
                      <button
                        type="button"
                        className="btn ghost sm"
                        onClick={() => setOpenId(isOpen ? null : a.id)}
                      >
                        {isOpen ? 'Hide' : 'Details ›'}
                      </button>
                    </div>

                    {isOpen && (
                      <div className="alerts-mitigation-panel" style={{ marginTop: 10 }}>
                        <div className="alerts-mit-box">
                          <small className="mono">WHAT HAPPENED</small>
                          <p>{adv.what}</p>
                        </div>
                        <div className="alerts-mit-box">
                          <small className="mono">RECOMMENDED DEFENSIVE ACTIONS</small>
                          <ul className="alerts-mit-list">
                            {adv.actions.map((x) => <li key={x}>{x}</li>)}
                          </ul>
                        </div>
                        {canEdit && (
                          <div className="alerts-status-controls">
                            <span className="mono alerts-status-label">STATUS:</span>
                            {STATUSES.map((s) => (
                              <button
                                key={s}
                                type="button"
                                className={'status-btn ' + s + (st === s ? ' active' : '')}
                                disabled={st === s}
                                onClick={() => changeStatus(a.id, s)}
                              >
                                {s}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}

        {/* Pagination Footer */}
        <div className="alerts-pagination">
          <span className="mono" style={{ color: 'var(--muted)', fontSize: 12.5 }}>
            {total ? `Showing ${offset + 1}–${Math.min(offset + PAGE, total)} of ${total.toLocaleString()} alerts` : '0 results'}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn ghost sm"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE))}
            >
              ← Previous
            </button>
            <button
              className="btn ghost sm"
              disabled={offset + PAGE >= total}
              onClick={() => setOffset(offset + PAGE)}
            >
              Next →
            </button>
          </div>
        </div>
      </div>

      {/* Confirm Block IP Dialog */}
      <BlockIpModal
        target={blockTarget}
        onClose={() => setBlockTarget(null)}
        onBlocked={(created) => {
          const ip = created?.ip || blockTarget?.ip || '';
          addOptimisticBlock(created);
          if (ip) setBlockToastIp(ip);
        }}
      />
    </div>
  );
}
