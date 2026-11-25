import { useState, useEffect, useRef, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { Link, useSearchParams } from 'react-router-dom';
import {
  usePolling,
  severity,
  sevColor,
  plainName,
  parseAlertTimeMs,
  getAdvice,
  suggestedSteps,
} from '../utils';
import { Skeleton, ErrorBox, SeverityBadge } from '../ui';
import { formatTimeParts, formatAbsoluteTime, downloadCSV } from '../format';
import { useAuth } from '../AuthContext';
import { alertsApi } from '../api';
import {
  useBlockedIps,
  BlockIpModal,
  BlockedIpChip,
} from '../BlockedIps';

const PAGE = 20;
const TYPES = ['', 'PortScan', 'BruteForce', 'DoS', 'Web Attack', 'Malware', 'UDP Flood', 'ICMP Flood'];
const GROUP_WINDOW_MS = 10 * 60 * 1000;

function isSuricataAlert(a) {
  return String(a?.source || '').toLowerCase() === 'suricata';
}

function sourceBadgeLabel(a) {
  return isSuricataAlert(a) ? 'Suricata' : 'ML/Rules';
}

function inferProtocol(a) {
  if (a?.protocol) return String(a.protocol).toUpperCase();
  const hay = `${a?.type || ''} ${a?.signature || ''} ${a?.detail || ''}`.toUpperCase();
  if (hay.includes('ICMP')) return 'ICMP';
  if (hay.includes('UDP')) return 'UDP';
  if (hay.includes('TCP') || hay.includes('SYN') || hay.includes('SSH') || hay.includes('HTTP') || hay.includes('MYSQL')) {
    return 'TCP';
  }
  const dp = String(a?.dport || '').trim();
  if (dp === '53' || dp === '123' || dp === '161') return 'UDP';
  if (dp && dp !== '-') return 'TCP';
  return '—';
}

function extractRelatedDetections(grp) {
  const out = [];
  const primary = grp.primary;

  // Include individual grouped alerts if multiple rows were grouped within 10 minutes
  if (grp.items.length > 1) {
    for (const item of grp.items) {
      out.push({
        label: item.signature || item.type || 'Detection',
        time: item.time,
      });
    }
  }

  // Also parse merged signatures from detail text if present (e.g. "3 merged signatures: A; B; C")
  const detailStr = String(primary?.detail || '');
  const m = detailStr.match(/(\d+)\s+(?:merged\s+signatures?|related\s+detections?)\s*:\s*(.+)$/i);
  if (m) {
    const names = m[2]
      .split(/[;,]/)
      .map((s) => s.trim())
      .filter(Boolean);
    const existing = new Set(out.map((x) => x.label.toLowerCase()));
    for (const name of names) {
      if (!existing.has(name.toLowerCase())) {
        out.push({ label: name, time: primary.time });
        existing.add(name.toLowerCase());
      }
    }
    return {
      totalCount: Math.max(Number(m[1]) || 0, out.length),
      items: out,
    };
  }

  return {
    totalCount: out.length,
    items: out,
  };
}

function extractMlInfo(a) {
  if (!a || isSuricataAlert(a)) return null;
  const scoreRaw = a.ml_score ?? a.confidence ?? a.score ?? null;
  let score = scoreRaw !== null && scoreRaw !== undefined ? String(scoreRaw) : '';
  const detail = String(a.detail || '');
  if (!score) {
    const sm = detail.match(/(?:conf(?:idence)?|score|prob(?:ability)?)\s*[=:]\s*([0-9.]+%?)/i);
    if (sm) score = sm[1];
  }
  let features = [];
  if (Array.isArray(a.top_features)) {
    features = a.top_features.map(String);
  } else if (Array.isArray(a.features)) {
    features = a.features.map(String);
  } else {
    const fm = detail.match(/(?:top\s+features?|features?|shap)\s*[:=]\s*([^|]+)/i);
    if (fm) {
      features = fm[1]
        .split(/[,;]/)
        .map((s) => s.trim())
        .filter(Boolean);
    }
  }
  const isMlTyped =
    String(a.type || '').toLowerCase().includes('ml') ||
    Boolean(score) ||
    features.length > 0;
  if (!isMlTyped) return null;
  return { score: score || '—', features };
}

function groupRepeatedAlerts(list) {
  const groups = [];
  for (const a of list) {
    const sigKey = String(a.signature || a.type || '').trim().toLowerCase();
    const srcKey = String(a.src || '').trim();
    const dstKey = String(a.dst || '').trim();
    const tMs = parseAlertTimeMs(a.time);

    let matched = null;
    for (const g of groups) {
      if (g.sigKey === sigKey && g.srcKey === srcKey && g.dstKey === dstKey) {
        if (isNaN(tMs) || isNaN(g.anchorMs) || Math.abs(g.anchorMs - tMs) <= GROUP_WINDOW_MS) {
          matched = g;
          break;
        }
      }
    }
    if (matched) {
      matched.items.push(a);
    } else {
      groups.push({
        key: `grp-${a.id}`,
        primary: a,
        items: [a],
        sigKey,
        srcKey,
        dstKey,
        anchorMs: tMs,
      });
    }
  }
  return groups;
}

function CopyIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
    </svg>
  );
}

function buildVerdict(a, sev, mlInfo) {
  let confidenceText = 'Confirmed rule pattern';
  let confidenceNote = '';
  if (isSuricataAlert(a)) {
    confidenceText = 'Confirmed pattern';
    confidenceNote = 'Suricata signature';
  } else if (mlInfo && mlInfo.score && mlInfo.score !== '—') {
    const rawNum = parseFloat(String(mlInfo.score).replace('%', ''));
    const pct = !isNaN(rawNum) ? (rawNum <= 1 ? Math.round(rawNum * 100) : Math.round(rawNum)) : null;
    if (pct !== null) {
      confidenceText = pct >= 90 ? 'Very likely' : pct >= 80 ? 'Likely' : 'Uncertain';
      confidenceNote = `${pct}% ML confidence`;
    } else {
      confidenceText = 'Likely';
      confidenceNote = `ML score ${mlInfo.score}`;
    }
  }

  const riskBySev = {
    Critical: {
      text: 'Critical risk — can slow or knock your network offline',
      color: 'var(--danger)',
      rec: 'Block this IP right away if you do not recognize the device.',
    },
    High: {
      text: 'High risk — attacker may be trying to break in',
      color: 'var(--high)',
      rec: 'Block this IP if you do not recognize the device, then check login security.',
    },
    Medium: {
      text: 'Medium risk — early probing; watch for follow-up activity',
      color: 'var(--warn)',
      rec: 'Monitor this source IP and block it if scanning continues.',
    },
    Low: {
      text: 'Low risk — minor or informational network activity',
      color: 'var(--low)',
      rec: 'No urgent action needed; mark as investigated once reviewed.',
    },
  };
  const risk = riskBySev[sev] || riskBySev.Medium;
  return { confidenceText, confidenceNote, risk };
}

function AlertDetailsModal({
  group,
  status,
  activeBlock,
  isViewer,
  statusMsg,
  onClose,
  onBlock,
  onUnblock,
  onMarkInvestigated,
}) {
  const modalRef = useRef(null);
  const closeBtnRef = useRef(null);
  const [sigCopied, setSigCopied] = useState(false);
  const [allCopied, setAllCopied] = useState(false);
  const [showAllRelated, setShowAllRelated] = useState(false);

  const a = group.primary;
  const sev = severity(a.type);
  const adv = getAdvice(a.type);
  const steps = suggestedSteps(a.type);
  const tp = formatTimeParts(a.time);
  const protocol = inferProtocol(a);
  const rawSignature = a.signature
    ? `${a.signature}${a.signature_id != null ? ` (SID ${a.signature_id})` : ''}`
    : a.type;
  const related = useMemo(() => extractRelatedDetections(group), [group]);
  const mlInfo = useMemo(() => extractMlInfo(a), [a]);
  const verdict = useMemo(() => buildVerdict(a, sev, mlInfo), [a, sev, mlInfo]);
  const destText = `${a.dst || '-'}${a.dport && a.dport !== '-' ? ':' + a.dport : ''}`;

  // Lock scroll, focus close button, handle Escape & focus trap
  useEffect(() => {
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeBtnRef.current?.focus();

    const onKeyDown = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key === 'Tab' && modalRef.current) {
        const focusables = modalRef.current.querySelectorAll(
          'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'
        );
        if (!focusables.length) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey) {
          if (document.activeElement === first || !modalRef.current.contains(document.activeElement)) {
            e.preventDefault();
            last.focus();
          }
        } else if (document.activeElement === last || !modalRef.current.contains(document.activeElement)) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = prevOverflow;
    };
  }, [onClose]);

  async function copyText(text, setFlag) {
    try {
      await navigator.clipboard.writeText(text);
      setFlag(true);
      setTimeout(() => setFlag(false), 1800);
    } catch {
      /* ignore clipboard restrictions */
    }
  }

  function handleCopyAll() {
    const lines = [
      `Alert #${a.id}: ${plainName(a.type, a)} (${sev})`,
      `Status: ${status}`,
      `Source: ${sourceBadgeLabel(a)}`,
      `Time: ${formatAbsoluteTime(a.time)}`,
      `Protocol: ${protocol}`,
      `Traffic: ${a.src || '-'} -> ${destText}`,
      `Signature: ${rawSignature}`,
    ];
    if (a.detail) lines.push(`Detail: ${a.detail}`);
    copyText(lines.join('\n'), setAllCopied);
  }

  const visibleRelated =
    showAllRelated || related.items.length <= 5
      ? related.items
      : related.items.slice(0, 5);

  return createPortal(
    <div
      className="ad-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={modalRef}
        className="ad-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="alert-modal-title"
      >
        {/* 1. Header */}
        <div className="ad-head">
          <div className="ad-head-main">
            <h2 id="alert-modal-title" className="ad-title">
              {plainName(a.type, a)}
            </h2>
            <div className="ad-badges">
              <SeverityBadge level={sev} />
              <span className={'status-pill ' + status}>
                <i /> {status}
              </span>
              {group.items.length > 1 && (
                <span className="alerts-group-badge mono">x{group.items.length}</span>
              )}
            </div>
          </div>
          <button
            ref={closeBtnRef}
            type="button"
            className="ad-close"
            onClick={onClose}
            aria-label="Close alert details"
          >
            ✕
          </button>
        </div>

        {/* Confidence + Risk Verdict */}
        <section className="ad-verdict-card" aria-label="Confidence and risk assessment">
          <div className="ad-verdict-grid">
            <div className="ad-verdict-col">
              <span className="ad-verdict-label">How sure we are</span>
              <span className="ad-verdict-val">
                {verdict.confidenceText}
                {verdict.confidenceNote && (
                  <span className="mono" style={{ color: 'var(--accent)', fontSize: 12, marginLeft: 6 }}>
                    ({verdict.confidenceNote})
                  </span>
                )}
              </span>
            </div>
            <div className="ad-verdict-col">
              <span className="ad-verdict-label">How risky it is</span>
              <span className="ad-verdict-val" style={{ color: verdict.risk.color }}>
                {verdict.risk.text}
              </span>
            </div>
          </div>
          <div className="ad-verdict-rec">
            <span className="ad-verdict-dot" aria-hidden="true" />
            <span><strong>Recommended:</strong> {verdict.risk.rec}</span>
          </div>
        </section>

        {/* 2. Summary */}
        <section className="ad-sec">
          <div className="ad-sec-label">Summary</div>
          <p className="ad-summary">{adv.what}</p>
        </section>

        {/* 3. Info grid */}
        <section className="ad-sec">
          <div className="ad-sec-label">Details</div>
          <div className="ad-info-grid">
            <div className="ad-info-item">
              <small>Detection source</small>
              <div>
                <span className={'alerts-source-badge ' + (isSuricataAlert(a) ? 'suricata' : 'sensor')}>
                  {sourceBadgeLabel(a)}
                </span>
              </div>
            </div>
            <div className="ad-info-item">
              <small>Time</small>
              <b className="mono" title={formatAbsoluteTime(a.time)}>
                {tp.date}{tp.age ? ` (${tp.age})` : ''}
              </b>
            </div>
            <div className="ad-info-item">
              <small>Protocol</small>
              <b className="mono">{protocol}</b>
            </div>
            <div className="ad-info-item">
              <small>Source IP</small>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                <b className="mono">{a.src || '—'}</b>
                {activeBlock && <BlockedIpChip blockRow={activeBlock} />}
              </div>
            </div>
            <div className="ad-info-item">
              <small>Destination IP:port</small>
              <b className="mono">{destText}</b>
            </div>
          </div>
        </section>

        {/* 4. Signature */}
        <section className="ad-sec">
          <div className="ad-sec-label">Signature</div>
          <div className="ad-sig-box">
            <code className="ad-sig-text mono">{rawSignature}</code>
            <button
              type="button"
              className="ad-copy-icon"
              onClick={() => copyText(rawSignature, setSigCopied)}
              aria-label="Copy signature"
              title="Copy signature"
            >
              <CopyIcon />
              <span>{sigCopied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </section>

        {/* 5. Related detections */}
        {related.totalCount > 0 && (
          <section className="ad-sec">
            <div className="ad-sec-label">
              Related detections ({related.totalCount})
            </div>
            <div className="ad-rel-list">
              {visibleRelated.map((item, idx) => {
                const itp = formatTimeParts(item.time);
                return (
                  <div key={`${item.label}-${idx}`} className="ad-rel-row">
                    <span className="ad-rel-name mono">{item.label}</span>
                    <span className="ad-rel-time mono">
                      {itp.date}{itp.age ? ` · ${itp.age}` : ''}
                    </span>
                  </div>
                );
              })}
            </div>
            {related.items.length > 5 && (
              <div>
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() => setShowAllRelated((v) => !v)}
                >
                  {showAllRelated
                    ? 'Show fewer'
                    : `Show all ${related.items.length} detections`}
                </button>
              </div>
            )}
          </section>
        )}

        {/* 6. ML info (ML alerts only) */}
        {mlInfo && (
          <section className="ad-sec">
            <div className="ad-sec-label">ML model info</div>
            <div className="ad-info-grid">
              <div className="ad-info-item">
                <small>Confidence score</small>
                <b className="mono">{mlInfo.score}</b>
              </div>
              <div className="ad-info-item">
                <small>Top features</small>
                <span>{mlInfo.features.length ? mlInfo.features.join(', ') : 'Flow anomaly signature'}</span>
              </div>
            </div>
          </section>
        )}

        {/* 7. What to do */}
        <section className="ad-sec">
          <div className="ad-sec-label">What to do</div>
          <ol className="ad-steps">
            {steps.map((s) => <li key={s}>{s}</li>)}
          </ol>
        </section>

        {statusMsg && (
          <div style={{ color: 'var(--danger)', fontSize: 13 }}>{statusMsg}</div>
        )}

        {/* 8. Actions row */}
        <div className="ad-actions">
          {!isViewer && a.src && a.src !== '-' && (
            activeBlock ? (
              <button
                type="button"
                className="btn ghost"
                onClick={() => onUnblock(activeBlock)}
              >
                Unblock IP
              </button>
            ) : (
              <button
                type="button"
                className="btn"
                onClick={() => onBlock({ ip: a.src, alertId: a.id })}
              >
                Block IP
              </button>
            )
          )}

          {!isViewer && (
            <button
              type="button"
              className="btn ghost"
              disabled={status === 'investigating'}
              onClick={() => onMarkInvestigated(a.id)}
            >
              {status === 'investigating' ? 'Investigated' : 'Mark investigated'}
            </button>
          )}

          <Link
            to={`/assistant?alert=${a.id}`}
            className="btn ghost"
            onClick={onClose}
          >
            Explain with AI
          </Link>

          <button
            type="button"
            className="btn ghost"
            onClick={handleCopyAll}
          >
            {allCopied ? 'Copied details' : 'Copy details'}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}

export default function Alerts() {
  const [searchParams] = useSearchParams();
  const [type, setType] = useState(() => {
    const t = searchParams.get('type') || '';
    return TYPES.includes(t) ? t : '';
  });
  const [sourceF, setSourceF] = useState('');
  const [q, setQ] = useState('');
  const [qd, setQd] = useState('');
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState(null);
  const alertParam = searchParams.get('alert');
  const targetAlertId =
    alertParam && /^\d+$/.test(alertParam.trim()) ? Number(alertParam.trim()) : null;
  const [deepLinkedAlert, setDeepLinkedAlert] = useState(null);
  const [highlightedId, setHighlightedId] = useState(null);
  const handledAlertParamRef = useRef(null);
  const lastTriggerRef = useRef(null);
  const { token, user } = useAuth();
  const isViewer = String(user?.role || '').toLowerCase() === 'viewer';
  const [statusF, setStatusF] = useState('');
  const [sevF, setSevF] = useState(() => {
    const s = searchParams.get('sev') || '';
    return ['Critical', 'High', 'Medium'].includes(s) ? s : '';
  });
  const [local, setLocal] = useState({});
  const [msg, setMsg] = useState('');
  const [freshIds, setFreshIds] = useState(new Set());
  const [blockTarget, setBlockTarget] = useState(null);
  const [blockToastIp, setBlockToastIp] = useState('');
  const seenRef = useRef(null);

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

  const path = `/?limit=${PAGE}&offset=${offset}&type=${encodeURIComponent(type)}&source=${encodeURIComponent(sourceF)}&q=${encodeURIComponent(qd)}&status=${statusF}`;
  const { data, error } = usePolling(path);
  const total = data ? data.total : 0;
  const filtered = Boolean(type || sourceF || q || statusF || sevF);

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

  const loadedAlerts = useMemo(() => {
    const base = data?.alerts || [];
    if (deepLinkedAlert && !base.some((a) => Number(a.id) === Number(deepLinkedAlert.id))) {
      return [deepLinkedAlert, ...base];
    }
    return base;
  }, [data, deepLinkedAlert]);

  useEffect(() => {
    if (!targetAlertId || !data) return;
    if (handledAlertParamRef.current === targetAlertId) return;

    const base = data?.alerts || [];
    const found = base.find((a) => Number(a.id) === targetAlertId);
    if (found) {
      handledAlertParamRef.current = targetAlertId;
      setSelectedId(found.id);
      setHighlightedId(found.id);
      return;
    }

    handledAlertParamRef.current = targetAlertId;
    alertsApi(`/${targetAlertId}`, { token })
      .then((res) => {
        if (res && res.id) {
          setDeepLinkedAlert(res);
          setSelectedId(res.id);
          setHighlightedId(res.id);
        }
      })
      .catch(() => {});
  }, [targetAlertId, data, token]);

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

  const groupedAlerts = useMemo(() => groupRepeatedAlerts(visibleAlerts), [visibleAlerts]);

  const activeModalGroup = useMemo(() => {
    if (selectedId === null) return null;
    return (
      groupedAlerts.find((g) => g.items.some((item) => item.id === selectedId)) ||
      null
    );
  }, [groupedAlerts, selectedId]);

  function openDetails(id, triggerEl) {
    lastTriggerRef.current = triggerEl || document.activeElement;
    setMsg('');
    setSelectedId(id);
  }

  function closeDetails() {
    setSelectedId(null);
    const el = lastTriggerRef.current;
    if (el && typeof el.focus === 'function') {
      setTimeout(() => el.focus(), 0);
    }
  }

  function clearFilters() {
    setType('');
    setSourceF('');
    setQ('');
    setQd('');
    setStatusF('');
    setSevF('');
    setOffset(0);
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
            Threats detected on your network. Review them and block suspicious devices.
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
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            <span>Export CSV</span>
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

      {/* Filter Bar */}
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
            placeholder="Search by IP, port, or threat..."
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
          value={sourceF}
          aria-label="Filter by source"
          onChange={(e) => { setSourceF(e.target.value); setOffset(0); }}
        >
          <option value="">All sources</option>
          <option value="suricata">Suricata</option>
          <option value="sensor">ML/Rules</option>
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
            Reset
          </button>
        )}
      </div>

      {error && <ErrorBox message={error} />}

      {/* Alerts Table + Mobile Cards */}
      <div className="card alerts-table-card">
        {/* Integrated Severity Filter Bar */}
        <div className="alerts-table-headbar">
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
          {data && (
            <span className="alerts-headbar-meta mono">
              {groupedAlerts.length} {groupedAlerts.length === 1 ? 'event' : 'events'} on page
            </span>
          )}
        </div>

        {!data ? (
          <div style={{ display: 'grid', gap: 10, padding: '16px 20px' }}>
            {[0, 1, 2, 3, 4, 5, 6].map((i) => <Skeleton key={i} h={44} r={8} />)}
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
                    <th style={{ width: 152 }}>Time</th>
                    <th style={{ width: 102 }}>Severity</th>
                    <th>Attack</th>
                    <th style={{ width: 118 }}>Status</th>
                    <th style={{ width: 210 }}>Source → Target</th>
                    <th style={{ width: 116, textAlign: 'right' }} aria-label="Actions" />
                  </tr>
                </thead>
                <tbody>
                  {groupedAlerts.map((grp) => {
                    const a = grp.primary;
                    const count = grp.items.length;
                    const sev = severity(a.type);
                    const adv = getAdvice(a.type);
                    const isFresh = grp.items.some((item) => freshIds.has(item.id));
                    const isDeepLinked = grp.items.some((item) => highlightedId === item.id);
                    const st = local[a.id] ?? a.status ?? 'new';
                    const activeBlock = activeMap.get(a.src);
                    const tp = formatTimeParts(a.time);
                    const dest = `${a.dst || '-'}${a.dport && a.dport !== '-' ? ':' + a.dport : ''}`;

                    return (
                      <tr
                        key={grp.key}
                        id={`alert-row-${a.id}`}
                        onClick={(e) => {
                          const btn = e.currentTarget.querySelector('button[data-details-btn]');
                          openDetails(a.id, btn || e.currentTarget);
                        }}
                        className={
                          'alerts-row' +
                          (isFresh ? ' row-flash' : '') +
                          (isDeepLinked ? ' alert-deeplink-highlight' : '')
                        }
                      >
                        <td
                          title={formatAbsoluteTime(a.time)}
                          className="mono alerts-time-cell"
                          style={{ boxShadow: `inset 3px 0 0 ${sevColor[sev]}` }}
                        >
                          <span className="alerts-time-main">{tp.date}</span>
                          {tp.age && <span className="alerts-time-age">{tp.age}</span>}
                        </td>
                        <td>
                          <SeverityBadge level={sev} />
                        </td>
                        <td className="alerts-type-cell">
                          <div className="alerts-type-wrap">
                            <span className="alert-plain-title">{plainName(a.type, a)}</span>
                            {count > 1 && (
                              <span className="alerts-group-badge mono" title={`${count} repeated alerts within 10 minutes`}>
                                ×{count}
                              </span>
                            )}
                          </div>
                          <span className="alerts-attack-sub">{adv.what}</span>
                        </td>
                        <td>
                          <span className={'status-pill ' + st}>
                            <i /> {st}
                          </span>
                        </td>
                        <td className="mono alerts-srcdst-cell">
                          <div className="alerts-ip-stack">
                            <div className="alerts-ip-src-line">
                              <span className="alerts-ip-src">{a.src || '—'}</span>
                              {activeBlock && <BlockedIpChip blockRow={activeBlock} />}
                            </div>
                            <span className="alerts-ip-dst">→ {dest}</span>
                          </div>
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <button
                            type="button"
                            data-details-btn
                            className="btn ghost sm alerts-details-btn"
                            onClick={(e) => {
                              e.stopPropagation();
                              openDetails(a.id, e.currentTarget);
                            }}
                          >
                            Details
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Mobile Alert Cards */}
            <div className="alerts-mobile-list">
              {groupedAlerts.map((grp) => {
                const a = grp.primary;
                const count = grp.items.length;
                const sev = severity(a.type);
                const adv = getAdvice(a.type);
                const isFresh = grp.items.some((item) => freshIds.has(item.id));
                const isDeepLinked = grp.items.some((item) => highlightedId === item.id);
                const st = local[a.id] ?? a.status ?? 'new';
                const tp = formatTimeParts(a.time);
                const dest = `${a.dst || '-'}${a.dport && a.dport !== '-' ? ':' + a.dport : ''}`;

                return (
                  <div
                    key={grp.key}
                    id={`alert-mcard-${a.id}`}
                    className={
                      'alerts-mcard' +
                      (isFresh ? ' row-flash' : '') +
                      (isDeepLinked ? ' alert-deeplink-highlight' : '')
                    }
                    style={{ borderLeft: `3px solid ${sevColor[sev]}` }}
                    onClick={(e) => {
                      const btn = e.currentTarget.querySelector('button[data-details-btn]');
                      openDetails(a.id, btn || e.currentTarget);
                    }}
                  >
                    <div className="alerts-mcard-top" style={{ cursor: 'pointer' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <SeverityBadge level={sev} />
                        {count > 1 && (
                          <span className="alerts-group-badge mono">x{count}</span>
                        )}
                        <span className={'status-pill ' + st}>
                          <i /> {st}
                        </span>
                      </div>
                      <div className="mono" title={formatAbsoluteTime(a.time)} style={{ textAlign: 'right' }}>
                        <span className="alerts-time-main">{tp.date}</span>
                        {tp.age && <span className="alerts-time-age">{tp.age}</span>}
                      </div>
                    </div>

                    <div style={{ marginTop: 4 }}>
                      <strong className="alert-plain-title">{plainName(a.type, a)}</strong>
                      <span className="alerts-attack-sub">{adv.what}</span>
                    </div>

                    <div className="alerts-mcard-ips mono">
                      <span>{a.src || '-'} → {dest}</span>
                      {activeMap.get(a.src) && <BlockedIpChip blockRow={activeMap.get(a.src)} />}
                    </div>

                    <div className="alerts-mcard-actions">
                      <button
                        type="button"
                        data-details-btn
                        className="btn ghost sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          openDetails(a.id, e.currentTarget);
                        }}
                      >
                        View details
                      </button>
                    </div>
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

      {/* Alert Details Modal / Bottom Sheet */}
      {activeModalGroup && (
        <AlertDetailsModal
          group={activeModalGroup}
          status={local[activeModalGroup.primary.id] ?? activeModalGroup.primary.status ?? 'new'}
          activeBlock={activeMap.get(activeModalGroup.primary.src)}
          isViewer={isViewer}
          statusMsg={msg}
          onClose={closeDetails}
          onBlock={(t) => setBlockTarget(t)}
          onUnblock={(blk) => unblockIp(blk)}
          onMarkInvestigated={(id) => changeStatus(id, 'investigating')}
        />
      )}

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
