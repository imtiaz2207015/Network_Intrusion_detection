import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useBlockedIps, formatRemaining } from '../BlockedIps';
import { formatTimeParts, formatAbsoluteTime } from '../format';
import { plainName } from '../utils';
import { useAuth } from '../AuthContext';
import { Skeleton, ErrorBox, Empty } from '../ui';

const HISTORY_PAGE_SIZE = 10;

function parseReasonDisplay(r) {
  const raw = String(r.reason || r.attack_type || r.type || '').trim();
  if (!raw) {
    return {
      title: 'Manual block',
      sub: '',
    };
  }
  // Extract leading attack token from patterns like "PortScan (Alert #14)" or "BruteForce x3 in 10 min (repeat offender, 24 h)"
  const baseAttack = raw.replace(/\s*\(Alert\s*#\d+\)\s*$/i, '').split(/\s+x\d+\b/i)[0].trim();
  const friendly = plainName(baseAttack);
  const cleanedRaw = raw.replace(/\s*\(Alert\s*#\d+\)\s*$/i, '').trim();
  const showSub = cleanedRaw && cleanedRaw.toLowerCase() !== friendly.toLowerCase();
  return {
    title: friendly,
    sub: showSub ? cleanedRaw : '',
  };
}

function sourceOf(r) {
  const s = String(r.source || (r.blocked_by === 'auto' ? 'auto' : 'manual')).toLowerCase();
  return s === 'auto' ? 'auto' : 'manual';
}

export default function BlockedIps() {
  const { user } = useAuth();
  const isViewer = String(user?.role || '').toLowerCase() === 'viewer';
  const {
    loading,
    error,
    activeList,
    historyList,
    toastErr,
    clearToast,
    unblockIp,
  } = useBlockedIps();

  const [histFilter, setHistFilter] = useState('all');
  const [visibleCount, setVisibleCount] = useState(HISTORY_PAGE_SIZE);

  const expiredCount = useMemo(
    () => historyList.filter((r) => String(r.status || '').toLowerCase() === 'expired').length,
    [historyList]
  );

  const unblockedCount = useMemo(
    () => historyList.filter((r) => String(r.status || '').toLowerCase() === 'unblocked').length,
    [historyList]
  );

  const sortedHistory = useMemo(() => {
    return [...historyList].sort((a, b) => {
      const ta = String(a.resolved_at || a.blocked_at || '');
      const tb = String(b.resolved_at || b.blocked_at || '');
      if (ta !== tb) return tb.localeCompare(ta);
      return (Number(b.id) || 0) - (Number(a.id) || 0);
    });
  }, [historyList]);

  const filteredHistory = useMemo(() => {
    if (histFilter === 'all') return sortedHistory;
    return sortedHistory.filter(
      (r) => String(r.status || '').toLowerCase() === histFilter
    );
  }, [sortedHistory, histFilter]);

  const visibleHistory = filteredHistory.slice(0, visibleCount);

  function selectHistFilter(f) {
    setHistFilter(f);
    setVisibleCount(HISTORY_PAGE_SIZE);
  }

  return (
    <div className="blk-page" style={{ display: 'grid', gap: 18 }}>
      <div>
        <h2>Blocked IPs</h2>
        <p className="band-sub">
          Devices currently blocked from your network and past block history.
        </p>
      </div>

      {error && <ErrorBox message={error} />}

      {toastErr && (
        <div className="help-banner err" role="alert" style={{ justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>!</span>
            <span>{toastErr}</span>
          </div>
          <button
            type="button"
            className="btn ghost sm"
            onClick={clearToast}
            aria-label="Dismiss error message"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Active Blocks */}
      <section className="card blk-section-card" aria-labelledby="active-blocks-heading">
        <div className="band-head">
          <div>
            <h3 id="active-blocks-heading">Active blocks</h3>
            <p className="band-sub">
              IP addresses currently blocked, with live expiration timers.
            </p>
          </div>
          <span className="badge mono">{activeList.length} active</span>
        </div>

        {loading ? (
          <div style={{ display: 'grid', gap: 10 }}>
            {[0, 1, 2].map((i) => <Skeleton key={i} h={46} r={8} />)}
          </div>
        ) : activeList.length === 0 ? (
          <div className="blk-empty">
            <div className="blk-empty-icon" aria-hidden="true">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
                <polyline points="9 12 11 14 15 10" />
              </svg>
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <p style={{ margin: 0, color: 'var(--text)', fontWeight: 500 }}>
                No IPs are blocked. You can block a suspicious device from any alert on the Alerts page.
              </p>
            </div>
            <Link to="/alerts" className="btn sm" style={{ whiteSpace: 'nowrap' }}>
              Go to Alerts
            </Link>
          </div>
        ) : (
          <>
            {/* Desktop Table (clean 5 columns) */}
            <div className="table-scroll-wrap blk-desktop-table">
              <table className="table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Reason</th>
                    <th>Blocked</th>
                    <th>Time Left</th>
                    {!isViewer && <th style={{ textAlign: 'right' }}>Action</th>}
                  </tr>
                </thead>
                <tbody>
                  {activeList.map((r) => {
                    const leftStr = formatRemaining(r.liveSeconds, r.status);
                    const isExpired = leftStr === 'expired';
                    const srcMode = sourceOf(r);
                    const reason = parseReasonDisplay(r);
                    const tp = formatTimeParts(r.blocked_at);
                    return (
                      <tr key={r.id}>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span className="mono" style={{ fontWeight: 600 }}>{r.ip}</span>
                            <span className={'blk-source-badge mono ' + srcMode}>
                              {srcMode === 'auto' ? 'Auto' : 'Manual'}
                            </span>
                          </div>
                        </td>
                        <td>
                          <span className="alert-plain-title">{reason.title}</span>
                          <div className="alerts-type-subline">
                            {reason.sub && <span className="alert-tech-sub">{reason.sub}</span>}
                            {r.alert_id && (
                              <Link to={`/alerts?alert=${r.alert_id}`} className="blk-alert-link mono" style={{ fontSize: 12 }}>
                                Alert #{r.alert_id} →
                              </Link>
                            )}
                          </div>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <span style={{ display: 'block', fontSize: 13 }}>{r.blocked_by || '—'}</span>
                          {r.blocked_at && (
                            <span className="alerts-time-age mono" title={formatAbsoluteTime(r.blocked_at)}>
                              {tp.date}{tp.age ? ` · ${tp.age}` : ''}
                            </span>
                          )}
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <span className={'blk-countdown mono' + (isExpired ? ' expired' : '')}>
                            {leftStr}
                          </span>
                        </td>
                        {!isViewer && (
                          <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                            <button
                              type="button"
                              className="btn ghost sm blk-unblock-btn"
                              onClick={() => unblockIp(r)}
                              aria-label={`Unblock ${r.ip}`}
                            >
                              Unblock
                            </button>
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Mobile Stacked Cards */}
            <div className="blk-mobile-cards">
              {activeList.map((r) => {
                const leftStr = formatRemaining(r.liveSeconds, r.status);
                const isExpired = leftStr === 'expired';
                const srcMode = sourceOf(r);
                const reason = parseReasonDisplay(r);
                const tp = formatTimeParts(r.blocked_at);
                return (
                  <div key={r.id} className="blk-mobile-card">
                    <div className="blk-mobile-top">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span className="mono blk-mobile-ip">{r.ip}</span>
                        <span className={'blk-source-badge mono ' + srcMode}>
                          {srcMode === 'auto' ? 'Auto' : 'Manual'}
                        </span>
                      </div>
                      <span className={'blk-countdown mono' + (isExpired ? ' expired' : '')}>
                        {leftStr}
                      </span>
                    </div>
                    <div style={{ marginTop: 2 }}>
                      <span className="alert-plain-title">{reason.title}</span>
                      {reason.sub && <span className="alert-tech-sub">{reason.sub}</span>}
                    </div>
                    <div className="blk-mobile-meta">
                      <span>Blocked by <b>{r.blocked_by || '—'}</b></span>
                      {r.alert_id && (
                        <Link to={`/alerts?alert=${r.alert_id}`} className="mono blk-alert-link">
                          Alert #{r.alert_id} →
                        </Link>
                      )}
                    </div>
                    {r.blocked_at && (
                      <div className="blk-mobile-meta mono" title={formatAbsoluteTime(r.blocked_at)}>
                        <span>{tp.date}{tp.age ? ` · ${tp.age}` : ''}</span>
                      </div>
                    )}
                    {!isViewer && (
                      <button
                        type="button"
                        className="btn ghost sm blk-unblock-btn"
                        style={{ width: '100%', marginTop: 6 }}
                        onClick={() => unblockIp(r)}
                        aria-label={`Unblock ${r.ip}`}
                      >
                        Unblock
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </section>

      {/* History Section */}
      <section className="card blk-section-card" aria-labelledby="history-blocks-heading">
        <div className="band-head">
          <div>
            <h3 id="history-blocks-heading">History</h3>
            <p className="band-sub">
              Previously blocked devices that have expired or been unblocked.
            </p>
          </div>
          <div className="alerts-sev-row" role="group" aria-label="Filter block history" style={{ margin: 0 }}>
            {[
              { key: 'all', label: 'All', count: sortedHistory.length },
              { key: 'expired', label: 'Expired', count: expiredCount },
              { key: 'unblocked', label: 'Unblocked', count: unblockedCount },
            ].map((chip) => {
              const active = histFilter === chip.key;
              return (
                <button
                  key={chip.key}
                  type="button"
                  aria-pressed={active}
                  className={'alerts-sev-pill' + (active ? ' active' : '')}
                  onClick={() => selectHistFilter(chip.key)}
                >
                  <span>{chip.label}</span>
                  <span className="mono alerts-sev-pill-count">{chip.count}</span>
                </button>
              );
            })}
          </div>
        </div>

        {loading ? (
          <div style={{ display: 'grid', gap: 10 }}>
            {[0, 1, 2].map((i) => <Skeleton key={i} h={42} r={8} />)}
          </div>
        ) : filteredHistory.length === 0 ? (
          <Empty
            title={sortedHistory.length === 0 ? 'No block history yet' : `No ${histFilter} entries`}
            note="Expired and manually unblocked IPs will appear here newest first."
          />
        ) : (
          <>
            {/* Desktop History Table (clean 5 columns) */}
            <div className="table-scroll-wrap blk-desktop-table">
              <table className="table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Reason</th>
                    <th>Status</th>
                    <th>Activity</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleHistory.map((h) => {
                    const stamp = h.resolved_at || h.blocked_at;
                    const st = String(h.status || 'expired').toLowerCase();
                    const srcMode = sourceOf(h);
                    const reason = parseReasonDisplay(h);
                    const tp = formatTimeParts(stamp);
                    return (
                      <tr key={h.id}>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span className="mono" style={{ fontWeight: 600 }}>{h.ip}</span>
                            <span className={'blk-source-badge mono ' + srcMode}>
                              {srcMode === 'auto' ? 'Auto' : 'Manual'}
                            </span>
                          </div>
                        </td>
                        <td>
                          <span className="alert-plain-title">{reason.title}</span>
                          <div className="alerts-type-subline">
                            {reason.sub && <span className="alert-tech-sub">{reason.sub}</span>}
                            {h.alert_id && (
                              <Link to={`/alerts?alert=${h.alert_id}`} className="blk-alert-link mono" style={{ fontSize: 12 }}>
                                Alert #{h.alert_id} →
                              </Link>
                            )}
                          </div>
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <span className={'blk-history-badge mono ' + st}>{st}</span>
                        </td>
                        <td>
                          <span style={{ display: 'block', fontSize: 13 }}>
                            Blocked by {h.blocked_by || '—'}
                          </span>
                          {h.resolved_by && (
                            <span className="alert-tech-sub">
                              {st} by {h.resolved_by}
                            </span>
                          )}
                        </td>
                        <td className="mono alerts-time-cell" title={formatAbsoluteTime(stamp)}>
                          <span className="alerts-time-main">{tp.date}</span>
                          {tp.age && <span className="alerts-time-age">{tp.age}</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Mobile History Cards */}
            <div className="blk-mobile-cards">
              {visibleHistory.map((h) => {
                const stamp = h.resolved_at || h.blocked_at;
                const st = String(h.status || 'expired').toLowerCase();
                const srcMode = sourceOf(h);
                const reason = parseReasonDisplay(h);
                const tp = formatTimeParts(stamp);
                return (
                  <div key={h.id} className="blk-mobile-card">
                    <div className="blk-mobile-top">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span className="mono blk-mobile-ip">{h.ip}</span>
                        <span className={'blk-source-badge mono ' + srcMode}>
                          {srcMode === 'auto' ? 'Auto' : 'Manual'}
                        </span>
                      </div>
                      <span className={'blk-history-badge mono ' + st}>{st}</span>
                    </div>
                    <div style={{ marginTop: 2 }}>
                      <span className="alert-plain-title">{reason.title}</span>
                      {reason.sub && <span className="alert-tech-sub">{reason.sub}</span>}
                    </div>
                    <div className="blk-mobile-meta">
                      <span>
                        Blocked by <b>{h.blocked_by || '—'}</b>
                        {h.resolved_by ? ` · ${st} by ${h.resolved_by}` : ''}
                      </span>
                      {h.alert_id && (
                        <Link to={`/alerts?alert=${h.alert_id}`} className="mono blk-alert-link">
                          Alert #{h.alert_id} →
                        </Link>
                      )}
                    </div>
                    {stamp && (
                      <div className="blk-mobile-meta mono" title={formatAbsoluteTime(stamp)}>
                        <span>{tp.date}{tp.age ? ` · ${tp.age}` : ''}</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {filteredHistory.length > visibleCount && (
              <div style={{ display: 'flex', justifyContent: 'center', marginTop: 14 }}>
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() => setVisibleCount((n) => n + HISTORY_PAGE_SIZE)}
                >
                  Show more ({filteredHistory.length - visibleCount} remaining)
                </button>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}
