import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useBlockedIps, formatRemaining } from '../BlockedIps';
import { formatTimestamp, formatAbsoluteTime, timeAgo } from '../format';
import { Skeleton, ErrorBox, Empty } from '../ui';

const HISTORY_PAGE_SIZE = 10;

function reasonOf(r) {
  if (r.reason) return r.reason;
  if (r.attack_type) return r.attack_type;
  if (r.type) return r.type;
  if (r.alert_id) return `Alert #${r.alert_id}`;
  return 'Manual block';
}

export default function BlockedIps() {
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
    <div className="blk-page" style={{ display: 'grid', gap: 16 }}>
      {/* a) Page Title & Subtitle */}
      <div>
        <h2>Blocked IPs</h2>
        <p className="band-sub">
          Source IPs on the blocklist, with live expiration countdowns.
        </p>
      </div>

      {/* b) Small Summary Row: Active, Expired, Unblocked */}
      <div className="blk-summary-row">
        <div className="card blk-summary-card">
          <span className="stat-label">Active</span>
          <b
            className="mono blk-summary-val"
            style={{ color: activeList.length > 0 ? 'var(--danger)' : 'var(--muted)' }}
          >
            {activeList.length}
          </b>
        </div>
        <div className="card blk-summary-card">
          <span className="stat-label">Expired</span>
          <b className="mono blk-summary-val" style={{ color: 'var(--warn)' }}>
            {expiredCount}
          </b>
        </div>
        <div className="card blk-summary-card">
          <span className="stat-label">Unblocked</span>
          <b className="mono blk-summary-val" style={{ color: 'var(--accent-2)' }}>
            {unblockedCount}
          </b>
        </div>
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

      {/* c) Active Blocks List */}
      <section className="card blk-section-card" aria-labelledby="active-blocks-heading">
        <div className="band-head">
          <div>
            <h3 id="active-blocks-heading">Active blocks</h3>
            <p className="band-sub">
              Currently active blocklist entries with real-time expiration timers.
            </p>
          </div>
          <span className="badge mono">{activeList.length} active</span>
        </div>

        {loading ? (
          <div style={{ display: 'grid', gap: 10 }}>
            {[0, 1, 2].map((i) => <Skeleton key={i} h={46} r={10} />)}
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
                No IPs are blocked. You can block a source IP from any alert on the Alerts page.
              </p>
            </div>
            <Link to="/alerts" className="btn sm" style={{ whiteSpace: 'nowrap' }}>
              Go to Alerts
            </Link>
          </div>
        ) : (
          <>
            {/* Desktop Table */}
            <div className="table-scroll-wrap blk-desktop-table">
              <table className="table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Blocked By</th>
                    <th>Reason / Source</th>
                    <th>Time Left</th>
                    <th style={{ textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {activeList.map((r) => {
                    const leftStr = formatRemaining(r.liveSeconds);
                    const isExpired = leftStr === 'expired';
                    return (
                      <tr key={r.id}>
                        <td className="mono" style={{ fontWeight: 600 }}>
                          {r.ip}
                        </td>
                        <td>
                          <span>{r.blocked_by || '—'}</span>
                          {r.blocked_at && (
                            <span
                              className="mono"
                              title={formatAbsoluteTime(r.blocked_at)}
                              style={{ color: 'var(--muted)', fontSize: 12, marginLeft: 8 }}
                            >
                              · {formatTimestamp(r.blocked_at)}
                            </span>
                          )}
                        </td>
                        <td className="mono" style={{ color: 'var(--muted)' }}>
                          {reasonOf(r)}
                        </td>
                        <td>
                          <span className={'blk-countdown mono' + (isExpired ? ' expired' : '')}>
                            {leftStr}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className="btn ghost sm blk-unblock-btn"
                            onClick={() => unblockIp(r)}
                            aria-label={`Unblock ${r.ip}`}
                          >
                            Unblock
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Mobile Stacked Cards (<= 768px) */}
            <div className="blk-mobile-cards">
              {activeList.map((r) => {
                const leftStr = formatRemaining(r.liveSeconds);
                const isExpired = leftStr === 'expired';
                return (
                  <div key={r.id} className="blk-mobile-card">
                    <div className="blk-mobile-top">
                      <span className="mono blk-mobile-ip">{r.ip}</span>
                    </div>
                    <div className="blk-mobile-status-row">
                      <span className="status-pill investigating">
                        <i /> active
                      </span>
                      <span className={'blk-countdown mono' + (isExpired ? ' expired' : '')}>
                        {leftStr}
                      </span>
                    </div>
                    <div className="blk-mobile-meta">
                      <span>Blocked by <b>{r.blocked_by || '—'}</b></span>
                      <span className="mono">{reasonOf(r)}</span>
                      {r.blocked_at && (
                        <span className="mono" title={formatAbsoluteTime(r.blocked_at)}>
                          {formatTimestamp(r.blocked_at)}
                        </span>
                      )}
                    </div>
                    <button
                      type="button"
                      className="btn ghost sm blk-unblock-btn"
                      style={{ width: '100%', marginTop: 4 }}
                      onClick={() => unblockIp(r)}
                      aria-label={`Unblock ${r.ip}`}
                    >
                      Unblock
                    </button>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </section>

      {/* d) History Section */}
      <section className="card blk-section-card" aria-labelledby="history-blocks-heading">
        <div className="band-head">
          <div>
            <h3 id="history-blocks-heading">History</h3>
            <p className="band-sub">
              Previously blocked source IPs that have expired or been manually unblocked.
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
            {[0, 1, 2].map((i) => <Skeleton key={i} h={42} r={10} />)}
          </div>
        ) : filteredHistory.length === 0 ? (
          <Empty
            icon="🕓"
            title={sortedHistory.length === 0 ? 'No block history yet' : `No ${histFilter} entries`}
            note="Expired and manually unblocked IPs will be logged here newest first."
          />
        ) : (
          <>
            {/* Desktop History Table */}
            <div className="table-scroll-wrap blk-desktop-table">
              <table className="table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Blocked By</th>
                    <th>Time</th>
                    <th>Age</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleHistory.map((h) => {
                    const stamp = h.resolved_at || h.blocked_at;
                    const st = String(h.status || 'expired').toLowerCase();
                    return (
                      <tr key={h.id}>
                        <td className="mono" style={{ fontWeight: 600 }}>
                          {h.ip}
                          {h.alert_id ? (
                            <span style={{ color: 'var(--muted)', fontSize: 12, marginLeft: 8 }}>
                              (Alert #{h.alert_id})
                            </span>
                          ) : null}
                        </td>
                        <td>
                          <span className={'blk-history-badge mono ' + st}>{st}</span>
                        </td>
                        <td>
                          <span>{h.blocked_by || '—'}</span>
                          {h.resolved_by && (
                            <span style={{ color: 'var(--muted)', fontSize: 12, marginLeft: 6 }}>
                              ({st} by {h.resolved_by})
                            </span>
                          )}
                        </td>
                        <td className="mono" title={formatAbsoluteTime(stamp)}>
                          {stamp ? formatAbsoluteTime(stamp) : '—'}
                        </td>
                        <td className="mono" style={{ color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                          {stamp ? timeAgo(stamp) : '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Mobile History Cards (<= 768px) */}
            <div className="blk-mobile-cards">
              {visibleHistory.map((h) => {
                const stamp = h.resolved_at || h.blocked_at;
                const st = String(h.status || 'expired').toLowerCase();
                return (
                  <div key={h.id} className="blk-mobile-card">
                    <div className="blk-mobile-top">
                      <span className="mono blk-mobile-ip">{h.ip}</span>
                      <span className={'blk-history-badge mono ' + st}>{st}</span>
                    </div>
                    <div className="blk-mobile-meta">
                      <span>
                        Blocked by <b>{h.blocked_by || '—'}</b>
                        {h.resolved_by ? ` · ${st} by ${h.resolved_by}` : ''}
                      </span>
                      {h.alert_id && <span className="mono">Alert #{h.alert_id}</span>}
                    </div>
                    {stamp && (
                      <div className="blk-mobile-meta mono" style={{ justifyContent: 'space-between' }}>
                        <span>{formatAbsoluteTime(stamp)}</span>
                        <span>{timeAgo(stamp)}</span>
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
