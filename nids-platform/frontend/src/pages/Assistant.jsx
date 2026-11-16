import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { alertsApi } from '../api';
import { useAuth } from '../AuthContext';
import { severity as sevOf } from '../utils';
import { formatTimestamp, formatAbsoluteTime } from '../format';
import { Skeleton, Empty } from '../ui';
import '../assistant.css';

function splitVerdict(text = '') {
  const str = String(text || '');
  const m = str.match(/^\[(HIGH|MEDIUM|LOW)\]\s*/i);
  if (!m) return { level: '', verdict: '', body: str };
  const rest = str.slice(m[0].length);
  const k = rest.search(/[.!?](\s|$)/);
  const level = m[1].toLowerCase();
  if (k < 0) return { level, verdict: rest, body: '' };
  return { level, verdict: rest.slice(0, k + 1), body: rest.slice(k + 1).trim() };
}

function dayKey(t = '') {
  return String(t || '').slice(0, 10);
}

function dayLabel(key) {
  const [y, m, d] = String(key || '').split('-').map(Number);
  if (!y || !m || !d) return key || 'Unknown date';
  const date = new Date(y, m - 1, d);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const diff = Math.round((today - date) / 86400000);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  return date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

function groupByDay(alerts) {
  const sorted = [...alerts].sort((a, b) => String(b.time || '').localeCompare(String(a.time || '')));
  const groups = [];
  for (const a of sorted) {
    const key = dayKey(a.time);
    let g = groups[groups.length - 1];
    if (!g || g.key !== key) {
      g = { key, label: dayLabel(key), items: [] };
      groups.push(g);
    }
    g.items.push(a);
  }
  return groups;
}

function portOf(a) {
  return a && a.dport && a.dport !== '-' ? ':' + a.dport : '';
}

function Chevron() {
  return (
    <svg className="as-chev" width="18" height="18" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

export default function Assistant() {
  const { token, user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [sel, setSel] = useState(null);
  const [res, setRes] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [closed, setClosed] = useState({});
  const [sevFilter, setSevFilter] = useState('');
  const [query, setQuery] = useState('');
  const [isMobile480, setIsMobile480] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(max-width: 480px)').matches
  );
  const reqId = useRef(0);
  const canRefresh = user?.role === 'admin' || user?.role === 'analyst';

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(max-width: 480px)');
    const onChange = (e) => setIsMobile480(e.matches);
    setIsMobile480(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    let alive = true;
    alertsApi('/?limit=100', { token })
      .then((d) => alive && setAlerts(Array.isArray(d?.alerts) ? d.alerts : []))
      .catch((e) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [token]);

  const filteredAlerts = useMemo(() => {
    const q = query.trim().toLowerCase();
    return alerts.filter((a) => {
      if (sevFilter && sevOf(a.type) !== sevFilter) return false;
      if (!q) return true;
      return (
        String(a.type || '').toLowerCase().includes(q) ||
        String(a.src || '').toLowerCase().includes(q) ||
        String(a.dst || '').toLowerCase().includes(q) ||
        String(a.dport || '').toLowerCase().includes(q) ||
        String(a.detail || '').toLowerCase().includes(q)
      );
    });
  }, [alerts, sevFilter, query]);

  const groups = useMemo(() => groupByDay(filteredAlerts), [filteredAlerts]);

  useEffect(() => {
    if (!sel) return;
    const onKey = (e) => e.key === 'Escape' && close();
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [sel]);

  function toggleDay(key) {
    setClosed((c) => ({ ...c, [key]: !c[key] }));
  }

  async function explainFor(a, refresh) {
    const id = ++reqId.current;
    setBusy(true);
    setError('');
    try {
      const r = await alertsApi(`/${a.id}/explain${refresh ? '?refresh=1' : ''}`, { token });
      if (id === reqId.current) setRes(r);
    } catch (e) {
      if (id === reqId.current) setError(e.message);
    } finally {
      if (id === reqId.current) setBusy(false);
    }
  }

  function open(a) {
    setSel(a);
    setRes(null);
    setError('');
    explainFor(a, false);
  }

  function close() {
    reqId.current++;
    setSel(null);
    setRes(null);
    setBusy(false);
    setError('');
  }

  const sev = sel ? sevOf(sel.type) : '';
  const v = res ? splitVerdict(res.what) : null;
  const stepsList = Array.isArray(res?.steps) ? res.steps : [];

  const modal = sel && (
    <div className="as-overlay" onClick={close}>
      <section className="as-modal" onClick={(e) => e.stopPropagation()}>
        <button className="as-x" onClick={close} aria-label="Close">✕</button>

        <div className="as-top">
          <span className={'as-badge as-' + sev.toLowerCase()}>{sev}</span>
          <h2>{sel.type}</h2>
          <span className="mono as-alert-id">Alert #{sel.id}</span>
        </div>

        <div className="as-ipbox">
          <div><small>Source (attacker)</small><b>{sel.src || '—'}</b></div>
          <div><small>Target</small><b>{sel.dst || '-'}{portOf(sel)}</b></div>
          <div><small>Time</small><b className="mono" title={formatAbsoluteTime(sel.time)}>{formatTimestamp(sel.time)}</b></div>
        </div>
        {sel.detail && <p className="as-detail mono">{sel.detail}</p>}

        {busy && (
          <div className="as-thinking">
            <span className="as-spinner" />
            <span>Synthesizing incident explanation &amp; mitigation playbook...</span>
          </div>
        )}
        {error && <p className="as-error">{error}</p>}

        {res && (
          <div className="as-res">
            <div className="as-res-meta">
              <span className={'as-from mono' + (res.source === 'claude' ? ' claude' : '')}>
                {res.source === 'claude' ? '✦ Explained by Claude AI' : '⚡ Built-in Security Playbook'}
                {res.cached ? ' · saved' : ''}
              </span>
              {res.note && <span className="as-note-inline">{res.note}</span>}
            </div>

            {v && v.level && <div className={'as-verdict as-v-' + v.level}>{v.verdict}</div>}

            <div className="as-card">
              <h3>What happened</h3>
              <p>{v && v.level ? (v.body || v.verdict) : (res.what || 'Suspicious network flow detected.')}</p>
            </div>
            <div className="as-card">
              <h3>How serious</h3>
              <p>{res.risk || 'Requires analyst verification.'}</p>
            </div>
            {stepsList.length > 0 && (
              <div className="as-card">
                <h3>What to do</h3>
                <ol>
                  {stepsList.map((s, i) => <li key={i}>{s}</li>)}
                </ol>
              </div>
            )}
            {res.source === 'claude' && (
              <p className="as-note">AI-generated analysis. Verify against firewall rules before blocking production hosts.</p>
            )}
          </div>
        )}

        <div className="as-actions">
          {canRefresh && res && res.ai_enabled && (
            <button className="as-btn ghost" onClick={() => explainFor(sel, true)} disabled={busy}>
              ↻ Ask Claude again
            </button>
          )}
          <button className="as-btn ghost" onClick={close}>Close</button>
        </div>
      </section>
    </div>
  );

  return (
    <div className="as">
      <div className="card as-banner">
        <div className="as-banner-left">
          <div className="as-banner-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3l1.9 5.8a2 2 0 001.3 1.3L21 12l-5.8 1.9a2 2 0 00-1.3 1.3L12 21l-1.9-5.8a2 2 0 00-1.3-1.3L3 12l5.8-1.9a2 2 0 001.3-1.3L12 3z" />
            </svg>
          </div>
          <div>
            <h2>AI Incident Assistant</h2>
            <p className="band-sub">
              Click <b>Explain</b> on any detection below to generate a plain-English root cause summary, severity verdict, and defensive checklist.
            </p>
          </div>
        </div>
        <div className="as-banner-right mono">
          <span>{filteredAlerts.length} alerts</span>
          <span>{groups.length} {groups.length === 1 ? 'day' : 'days'}</span>
        </div>
      </div>

      {/* Quick Filter Bar */}
      {!loading && alerts.length > 0 && (
        <div className="as-toolbar">
          <input
            className="input as-search"
            placeholder={
              isMobile480
                ? 'Search IP, port, attack'
                : 'Filter by source IP, target IP, port, or attack type...'
            }
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="as-sev-pills" role="group" aria-label="Filter by severity">
            {['', 'Critical', 'High', 'Medium'].map((sv) => (
              <button
                key={sv || 'all'}
                type="button"
                className={'an-pill' + (sevFilter === sv ? ' active' : '')}
                onClick={() => setSevFilter(sv)}
              >
                {sv || 'All'}
              </button>
            ))}
          </div>
        </div>
      )}

      {loading && (
        <div className="as-feed" style={{ display: 'grid', gap: 12 }}>
          {[0, 1, 2].map((i) => <Skeleton key={i} h={110} r={16} />)}
        </div>
      )}

      {!loading && filteredAlerts.length === 0 && (
        <div className="card as-feed">
          <Empty
            icon="🤖"
            title={alerts.length === 0 ? 'No alerts to explain yet' : 'No alerts match your filter'}
            note={
              alerts.length === 0
                ? 'Detections from the live sensor will be grouped by day here for instant AI triage.'
                : 'Try clearing your search or selecting All severities above.'
            }
          />
        </div>
      )}

      {!sel && error && <p className="as-error">{error}</p>}

      <div className="as-feed">
        {groups.map((g) => {
          const isClosed = !!closed[g.key];
          return (
            <div key={g.key} className={'as-day' + (isClosed ? ' closed' : '')}>
              <div
                className="as-day-head"
                role="button"
                tabIndex={0}
                aria-expanded={!isClosed}
                onClick={() => toggleDay(g.key)}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleDay(g.key))}
              >
                <div className="as-day-title">
                  <span>{g.label}</span>
                  <span className="mono as-day-date">{g.key}</span>
                </div>
                <span className="as-day-right">
                  <small className="mono">{g.items.length} {g.items.length === 1 ? 'alert' : 'alerts'}</small>
                  <Chevron />
                </span>
              </div>

              {!isClosed && (
                <div className="as-day-list">
                  {g.items.map((a) => {
                    const s = sevOf(a.type);
                    return (
                      <div key={a.id} className="as-row" onClick={() => open(a)}>
                        <i className={'as-dot as-' + s.toLowerCase()} />
                        <b className="as-r-type">{a.type}</b>
                        <span className="as-r-ip">{a.src} → {a.dst || '-'}{portOf(a)}</span>
                        <span className="as-r-time mono" title={formatAbsoluteTime(a.time)}>{formatTimestamp(a.time)}</span>
                        <span className={'as-badge as-' + s.toLowerCase()}>{s}</span>
                        <button
                          type="button"
                          className="as-btn sm as-explain-btn"
                          onClick={(e) => { e.stopPropagation(); open(a); }}
                        >
                          ✦ Explain
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {modal && createPortal(modal, document.body)}
    </div>
  );
}
