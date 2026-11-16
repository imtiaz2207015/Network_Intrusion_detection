import { useState, useEffect, useRef, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { usePolling } from './utils';
import { alertsApi } from './api';
import { useAuth } from './AuthContext';
import { formatTimestamp, formatAbsoluteTime } from './format';

const LIVE_STATUSES = new Set(['active', 'unblock_requested']);

export const DURATION_OPTIONS = [
  { value: 10, label: '10 min (default)' },
  { value: 30, label: '30 min' },
  { value: 60, label: '1 hour' },
  { value: 360, label: '6 hours' },
  { value: 1440, label: '24 hours' },
];

export function isCurrentlyBlocked(status) {
  return LIVE_STATUSES.has(status);
}

export function formatRemaining(sec) {
  if (sec === null || sec === undefined) return '—';
  if (sec <= 0) return 'expired';
  const s = Math.floor(sec);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  if (h > 0) {
    return `${h}h ${String(m).padStart(2, '0')}m ${String(r).padStart(2, '0')}s`;
  }
  if (m > 0) {
    return `${m}m ${String(r).padStart(2, '0')}s`;
  }
  return `${r}s`;
}

export function useBlockedIps() {
  const { token, user } = useAuth();
  const { data, error, reload } = usePolling('/blocked-ips', 5000);
  const [rows, setRows] = useState([]);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [toastErr, setToastErr] = useState('');
  const expiredRefetchedRef = useRef(new Set());

  // Sync rows when polled data arrives
  useEffect(() => {
    if (!data || !Array.isArray(data.blocked)) return;
    const stamp = Date.now();
    setNowMs(stamp);
    setRows(
      data.blocked.map((r) => ({
        ...r,
        _syncedAt: stamp,
      }))
    );
  }, [data]);

  // 1-second local countdown tick (paused when tab is hidden)
  const hasActive = useMemo(
    () => rows.some((r) => isCurrentlyBlocked(r.status)),
    [rows]
  );

  useEffect(() => {
    if (!hasActive) return;
    const id = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      setNowMs(Date.now());
    }, 1000);
    return () => clearInterval(id);
  }, [hasActive]);

  // Compute live seconds_left for each row
  const computedRows = useMemo(() => {
    return rows.map((r) => {
      if (!isCurrentlyBlocked(r.status) || r.seconds_left === null || r.seconds_left === undefined) {
        return { ...r, liveSeconds: null };
      }
      const elapsed = Math.max(0, Math.floor((nowMs - (r._syncedAt || nowMs)) / 1000));
      const left = Math.max(0, r.seconds_left - elapsed);
      return { ...r, liveSeconds: left };
    });
  }, [rows, nowMs]);

  // When an active countdown reaches 0, show "expired" and refetch once
  useEffect(() => {
    let shouldRefetch = false;
    for (const r of computedRows) {
      if (isCurrentlyBlocked(r.status) && r.liveSeconds === 0) {
        if (!expiredRefetchedRef.current.has(r.id)) {
          expiredRefetchedRef.current.add(r.id);
          shouldRefetch = true;
        }
      }
    }
    if (shouldRefetch) {
      const t = setTimeout(() => reload(), 650);
      return () => clearTimeout(t);
    }
  }, [computedRows, reload]);

  const activeList = useMemo(
    () => computedRows.filter((r) => isCurrentlyBlocked(r.status)),
    [computedRows]
  );

  const historyList = useMemo(
    () => computedRows.filter((r) => !isCurrentlyBlocked(r.status)),
    [computedRows]
  );

  const activeMap = useMemo(() => {
    const m = new Map();
    for (const r of activeList) {
      if (r.ip && !m.has(r.ip)) m.set(r.ip, r);
    }
    return m;
  }, [activeList]);

  function addOptimisticBlock(newRow) {
    const stamp = Date.now();
    setNowMs(stamp);
    setRows((prev) => [
      { ...newRow, _syncedAt: stamp },
      ...prev.filter((x) => x.id !== newRow.id),
    ]);
    reload();
  }

  async function unblockIp(row) {
    setToastErr('');
    const snapshot = rows;
    const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');
    // Optimistic update
    setRows((prev) =>
      prev.map((r) =>
        r.id === row.id
          ? {
            ...r,
            status: 'unblocked',
            resolved_by: user?.username || 'you',
            resolved_at: nowStr,
            seconds_left: null,
          }
          : r
      )
    );
    try {
      await alertsApi(`/blocked-ips/${row.id}/unblock`, {
        method: 'POST',
        token,
      });
      reload();
    } catch (err) {
      setRows(snapshot);
      setToastErr(err.message || 'Could not unblock IP.');
    }
  }

  return {
    loading: !data && !error,
    error,
    activeList,
    historyList,
    activeMap,
    toastErr,
    clearToast: () => setToastErr(''),
    unblockIp,
    addOptimisticBlock,
    reload,
  };
}

export function BlockIpModal({ target, onClose, onBlocked }) {
  const { token } = useAuth();
  const [minutes, setMinutes] = useState(10);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const dialogRef = useRef(null);
  const selectRef = useRef(null);

  useEffect(() => {
    if (!target) return;
    setMinutes(10);
    setErr('');
    setBusy(false);

    const prevFocus = document.activeElement;
    const focusTimer = setTimeout(() => {
      if (selectRef.current) selectRef.current.focus();
    }, 20);

    function onKeyDown(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key === 'Tab' && dialogRef.current) {
        const focusables = dialogRef.current.querySelectorAll(
          'button:not(:disabled), select:not(:disabled), input:not(:disabled), [tabindex]:not([tabindex="-1"])'
        );
        if (!focusables.length) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }

    window.addEventListener('keydown', onKeyDown);
    return () => {
      clearTimeout(focusTimer);
      window.removeEventListener('keydown', onKeyDown);
      if (prevFocus && typeof prevFocus.focus === 'function') {
        prevFocus.focus();
      }
    };
  }, [target, onClose]);

  if (!target) return null;

  async function handleConfirm(e) {
    e.preventDefault();
    setBusy(true);
    setErr('');
    try {
      const created = await alertsApi('/block-ip', {
        method: 'POST',
        token,
        body: {
          ip: target.ip,
          alert_id: target.alertId ?? null,
          minutes: Number(minutes),
        },
      });
      if (onBlocked) onBlocked(created);
      onClose();
    } catch (e2) {
      setErr(e2.message || 'Could not block this IP.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="blk-modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="card blk-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="blk-modal-title"
      >
        <div className="blk-modal-head">
          <div>
            <span className="mono blk-modal-kicker">DEFENSIVE CONTAINMENT</span>
            <h3 id="blk-modal-title">Block Source IP</h3>
          </div>
          <button
            type="button"
            className="btn ghost sm blk-close-btn"
            onClick={onClose}
            disabled={busy}
            aria-label="Close block IP dialog"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleConfirm} className="blk-modal-body">
          <div className="blk-target-box">
            <small className="mono">TARGET SOURCE IP</small>
            <strong className="mono">{target.ip}</strong>
            {target.alertId && (
              <span className="mono" style={{ color: 'var(--muted)', fontSize: 12 }}>
                Triggered by Alert #{target.alertId}
              </span>
            )}
          </div>

          <div className="help-field">
            <label htmlFor="blk-duration-select" style={{ fontSize: 13, fontWeight: 600 }}>
              Block duration
            </label>
            <select
              id="blk-duration-select"
              ref={selectRef}
              className="input"
              value={minutes}
              disabled={busy}
              onChange={(e) => setMinutes(Number(e.target.value))}
            >
              {DURATION_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <p className="blk-modal-note">
            This IP will remain on the blocklist until the timer ends. You can unblock it any time.
          </p>

          {err && (
            <div className="help-banner err" role="alert">
              <span>!</span>
              <span>{err}</span>
            </div>
          )}

          <div className="blk-modal-actions">
            <button
              type="button"
              className="btn ghost sm"
              onClick={onClose}
              disabled={busy}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn sm help-submit-btn"
              disabled={busy}
            >
              {busy && <span className="help-spinner" aria-hidden="true" />}
              <span>{busy ? 'Blocking...' : 'Confirm Block IP'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function BlockedIpChip({ blockRow }) {
  if (!blockRow) return null;
  const label = formatRemaining(blockRow.liveSeconds);
  return (
    <span className="blk-active-chip mono" title={`Blocked by ${blockRow.blocked_by || 'user'}`}>
      <span className="blk-chip-dot" aria-hidden="true" />
      <span>Blocked · {label}</span>
    </span>
  );
}

export function BlockedIpsSection({ blockedState, compact = false, id = 'blocked-ips' }) {
  const internalState = useBlockedIps();
  const state = blockedState || internalState;
  const { activeList, historyList, toastErr, clearToast, unblockIp } = state;
  const [showHistory, setShowHistory] = useState(false);

  const visibleActive = compact ? activeList.slice(0, 5) : activeList;
  const visibleHistory = compact ? historyList.slice(0, 6) : historyList.slice(0, 30);

  return (
    <section id={id} className="card blk-section-card" aria-labelledby={`${id}-heading`}>
      <div className="band-head">
        <div>
          <h3 id={`${id}-heading`}>Blocked IPs</h3>
          <p className="band-sub">
            Source IPs on the blocklist, with live expiration countdowns.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span className="badge mono">
            {activeList.length} active
          </span>
          {compact && (
            <Link to="/blocked" className="btn ghost sm">
              Manage all →
            </Link>
          )}
        </div>
      </div>

      {toastErr && (
        <div className="help-banner err" role="alert" style={{ marginBottom: 12, justifyContent: 'space-between' }}>
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

      {activeList.length === 0 ? (
        <div className="blk-empty">
          <div className="blk-empty-icon" aria-hidden="true">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
              <polyline points="9 12 11 14 15 10" />
            </svg>
          </div>
          <div>
            <strong>No IPs are blocked</strong>
            <p>You can block any suspicious source IP directly from an alert in the Alerts page.</p>
          </div>
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
                  <th>Time Left</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {visibleActive.map((r) => {
                  const leftStr = formatRemaining(r.liveSeconds);
                  const isExpired = leftStr === 'expired';
                  return (
                    <tr key={r.id}>
                      <td className="mono" style={{ fontWeight: 600 }}>
                        {r.ip}
                        {r.alert_id ? (
                          <span style={{ color: 'var(--muted)', fontSize: 11.5, marginLeft: 8 }}>
                            (Alert #{r.alert_id})
                          </span>
                        ) : null}
                      </td>
                      <td>
                        <span>{r.blocked_by || '—'}</span>
                        {r.blocked_at && (
                          <span
                            className="mono"
                            title={formatAbsoluteTime(r.blocked_at)}
                            style={{ color: 'var(--muted)', fontSize: 11.5, marginLeft: 8 }}
                          >
                            · {formatTimestamp(r.blocked_at)}
                          </span>
                        )}
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

          {/* Mobile Cards (<= 640px) */}
          <div className="blk-mobile-cards">
            {visibleActive.map((r) => {
              const leftStr = formatRemaining(r.liveSeconds);
              const isExpired = leftStr === 'expired';
              return (
                <div key={r.id} className="blk-mobile-card">
                  <div className="blk-mobile-top">
                    <span className="mono blk-mobile-ip">{r.ip}</span>
                    <span className={'blk-countdown mono' + (isExpired ? ' expired' : '')}>
                      {leftStr}
                    </span>
                  </div>
                  <div className="blk-mobile-meta">
                    <span>Blocked by <b>{r.blocked_by || '—'}</b></span>
                    {r.blocked_at && (
                      <span className="mono" title={formatAbsoluteTime(r.blocked_at)}>
                        {formatTimestamp(r.blocked_at)}
                      </span>
                    )}
                  </div>
                  <button
                    type="button"
                    className="btn ghost sm blk-unblock-btn"
                    style={{ width: '100%', marginTop: 6 }}
                    onClick={() => unblockIp(r)}
                    aria-label={`Unblock ${r.ip}`}
                  >
                    Unblock {r.ip}
                  </button>
                </div>
              );
            })}
          </div>
        </>
      )}

      {/* Collapsible Recent History (unblocked / expired) */}
      {historyList.length > 0 && (
        <div className="blk-history-wrap">
          <button
            type="button"
            className="blk-history-toggle"
            aria-expanded={showHistory}
            onClick={() => setShowHistory((v) => !v)}
          >
            <span>Recent history ({historyList.length})</span>
            <span className={'faq-chev' + (showHistory ? ' open' : '')} aria-hidden="true">▾</span>
          </button>

          {showHistory && (
            <div className="blk-history-list">
              {visibleHistory.map((h) => (
                <div key={h.id} className="blk-history-row">
                  <span className="mono blk-history-ip">{h.ip}</span>
                  <span className="blk-history-badge mono">{h.status}</span>
                  <span className="blk-history-meta">
                    blocked by {h.blocked_by || '—'}
                    {h.resolved_by ? ` · ${h.status} by ${h.resolved_by}` : ''}
                    {h.resolved_at ? (
                      <span className="mono" title={formatAbsoluteTime(h.resolved_at)}>
                        {' '}({formatTimestamp(h.resolved_at)})
                      </span>
                    ) : ''}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

