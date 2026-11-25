import { useState, useEffect, useRef, Fragment } from 'react';
import { Link } from 'react-router-dom';
import { usePolling, severity, plainName, getAdvice } from '../utils';
import { alertsApi } from '../api';
import { useAuth } from '../AuthContext';
import { CountUp, Skeleton, ErrorBox, Empty, SeverityBadge } from '../ui';
import { timeAgo, formatAbsoluteTime, parseTimeMs } from '../format';
import { BlockedIpsSection } from '../BlockedIps';
import { SENSOR_OFFLINE_GUIDE } from '../helpText';

function hourlyBuckets(alerts, hours = 12, nowMs = Date.now()) {
  const nowHour = Math.floor(nowMs / 3600000);
  const startHour = nowHour - (hours - 1);
  const counts = new Map();
  for (const a of alerts) {
    const ms = parseTimeMs(a.time);
    if (isNaN(ms)) continue;
    const h = Math.floor(ms / 3600000);
    if (h >= startHour && h <= nowHour) {
      counts.set(h, (counts.get(h) || 0) + 1);
    }
  }
  const out = [];
  for (let h = startHour; h <= nowHour; h++) {
    const d = new Date(h * 3600000);
    const hh = String(d.getHours()).padStart(2, '0');
    out.push({
      hour: h,
      label: `${hh}:00`,
      n: counts.get(h) || 0,
    });
  }
  return out;
}

export default function Dashboard() {
  const { token } = useAuth();
  const stats = usePolling('/stats');
  const recent = usePolling('/?limit=200');
  const sensor = usePolling('/sensor', 5000);

  const [openId, setOpenId] = useState(null);
  const [freshIds, setFreshIds] = useState(new Set());
  const [hoverIdx, setHoverIdx] = useState(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [showSensorGuide, setShowSensorGuide] = useState(() => {
    try {
      return sessionStorage.getItem('nids_sensor_guide') === 'open';
    } catch {
      return false;
    }
  });
  const [manualSensor, setManualSensor] = useState(null);
  const [checkingSensor, setCheckingSensor] = useState(false);
  const [checkMsg, setCheckMsg] = useState('');
  const seenIdsRef = useRef(null);

  function toggleSensorGuide() {
    setShowSensorGuide((prev) => {
      const next = !prev;
      try {
        sessionStorage.setItem('nids_sensor_guide', next ? 'open' : 'closed');
      } catch {
        /* ignore */
      }
      return next;
    });
  }

  useEffect(() => {
    if (!checkMsg) return;
    const t = setTimeout(() => setCheckMsg(''), 10000);
    return () => clearTimeout(t);
  }, [checkMsg]);

  async function checkSensorNow() {
    setCheckingSensor(true);
    setCheckMsg('');
    try {
      const res = await alertsApi('/sensor', { token });
      setManualSensor(res);
      if (res && res.online) {
        setCheckMsg('Connected! Your sensor is now Online and protecting your network.');
        setShowSensorGuide(false);
        try {
          sessionStorage.setItem('nids_sensor_guide', 'closed');
        } catch {
          /* ignore */
        }
      } else {
        setCheckMsg('Still offline — make sure the sensor box is plugged into power and connected to the same Wi-Fi.');
      }
    } catch {
      setCheckMsg('Could not reach the sensor status service. Please try again in a moment.');
    } finally {
      setCheckingSensor(false);
    }
  }

  useEffect(() => {
    const list = recent.data?.alerts;
    if (!list) return;
    if (seenIdsRef.current === null) {
      seenIdsRef.current = new Set(list.map((a) => a.id));
      return;
    }
    const arrived = list.filter((a) => !seenIdsRef.current.has(a.id));
    if (!arrived.length) return;

    arrived.forEach((a) => seenIdsRef.current.add(a.id));
    setFreshIds(new Set(arrived.map((a) => a.id)));

    const timer = setTimeout(() => {
      setFreshIds(new Set());
    }, 2400);
    return () => clearTimeout(timer);
  }, [recent.data]);

  useEffect(() => {
    const id = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      setNowMs(Date.now());
    }, 30000);
    return () => clearInterval(id);
  }, []);

  if (stats.error) return <ErrorBox message={stats.error} />;
  if (!stats.data || !recent.data) {
    return (
      <div className="dash-bands">
        <Skeleton h={82} r={8} />
        <div className="grid dash-kpis">
          {[0, 1, 2, 3].map((i) => <Skeleton key={i} h={104} r={8} />)}
        </div>
        <Skeleton h={240} r={8} />
        <Skeleton h={320} r={8} />
      </div>
    );
  }

  const { total, counts } = stats.data;
  const alerts = recent.data.alerts || [];
  const types = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const critical = types
    .filter(([t]) => severity(t) === 'Critical')
    .reduce((s, [, n]) => s + n, 0);

  const now = nowMs;
  const lastHourAlerts = alerts.filter((a) => {
    const ms = parseTimeMs(a.time);
    return !isNaN(ms) && now - ms <= 3600 * 1000;
  });
  const lastHourCount = lastHourAlerts.length;
  const lastHourUrgentCount = lastHourAlerts.filter((a) => {
    const s = severity(a.type);
    const st = String(a.status || 'new').toLowerCase();
    return st !== 'resolved' && (s === 'Critical' || s === 'High');
  }).length;

  const sData = manualSensor || sensor.data;
  const sensorOnline = !!(sData && sData.online);
  const latestAlert = alerts[0] || null;
  const lastThreatText = latestAlert ? `Last threat detected ${timeAgo(latestAlert.time)}` : 'No threats detected yet';

  const bannerMode = !sensorOnline
    ? 'offline'
    : lastHourUrgentCount > 0
      ? 'attention'
      : 'protected';

  const hourBars = hourlyBuckets(alerts, 12, now);
  const maxHour = Math.max(1, ...hourBars.map((b) => b.n));
  const totalInChart = hourBars.reduce((s, b) => s + b.n, 0);

  const topRaw = types[0] ? types[0][0] : '';
  const topPlain = topRaw ? plainName(topRaw) : '—';

  return (
    <div className="dash-bands">
      {/* PAGE HEADER */}
      <div className="dash-page-head">
        <div>
          <h1>Overview</h1>
          <p className="dash-page-sub">
            {sensorOnline
              ? 'Live network protection · Updated just now'
              : 'Network protection overview'}
          </p>
        </div>
      </div>

      {/* 1. STATUS BANNER */}
      <section className={`status-banner ${bannerMode}`} role="status">
        <div className="status-banner-left">
          <div className="status-banner-icon" aria-hidden="true">
            {bannerMode === 'attention' ? (
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
            ) : bannerMode === 'protected' ? (
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
                <polyline points="9 12 11 14 15 10" />
              </svg>
            ) : (
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
                <line x1="9" y1="9" x2="15" y2="15" />
                <line x1="15" y1="9" x2="9" y2="15" />
              </svg>
            )}
          </div>
          <div>
            <h2 className="status-banner-title">
              {bannerMode === 'attention'
                ? `${lastHourUrgentCount} ${lastHourUrgentCount === 1 ? 'threat needs' : 'threats need'} attention`
                : bannerMode === 'protected'
                  ? 'Your network is protected'
                  : 'Sensor is offline'}
            </h2>
            <p className="status-banner-sub">
              {bannerMode === 'attention'
                ? 'Detected in the last hour'
                : bannerMode === 'protected'
                  ? lastThreatText
                  : 'Start your sensor to resume protection'}
            </p>
          </div>
        </div>

        <div className="status-banner-actions">
          {bannerMode === 'attention' && (
            <Link to="/alerts" className="btn">Review now</Link>
          )}
          {bannerMode === 'offline' && (
            <button type="button" className="btn ghost" onClick={toggleSensorGuide}>
              {showSensorGuide ? 'Hide setup steps' : 'Show setup steps'}
            </button>
          )}
        </div>
      </section>

      {!sensorOnline && showSensorGuide && (
        <section className="card dash-sensor-guide">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div className="stat-label" style={{ marginBottom: 4 }}>{SENSOR_OFFLINE_GUIDE.title}</div>
              <p className="band-sub">{SENSOR_OFFLINE_GUIDE.subtitle}</p>
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn sm help-submit-btn"
                onClick={checkSensorNow}
                disabled={checkingSensor}
              >
                {checkingSensor && <span className="help-spinner" aria-hidden="true" />}
                <span>{checkingSensor ? 'Checking...' : 'Check Sensor Now'}</span>
              </button>
              <Link to="/settings#my-sensor" className="btn ghost sm">Settings &gt; My sensor</Link>
              <Link to="/help#offline" className="btn ghost sm">More Help</Link>
            </div>
          </div>

          <div className="dash-sensor-steps">
            {SENSOR_OFFLINE_GUIDE.steps.map((step) => (
              <div key={step.num} className="dash-sensor-step">
                <span className="dash-step-num mono">{step.num}</span>
                <div>
                  <b>{step.title}</b>
                  <p>{step.text}</p>
                </div>
              </div>
            ))}
          </div>

          {checkMsg && (
            <div className={'help-banner ' + (sensorOnline ? 'ok' : 'err')} role="status" style={{ marginTop: 12 }}>
              <span>{sensorOnline ? '✓' : 'i'}</span>
              <span>{checkMsg}</span>
            </div>
          )}
        </section>
      )}

      {/* 2. STAT CARDS */}
      <section className="grid dash-kpis">
        <Link to="/alerts" className="card kpi-card kpi-link">
          <div className="kpi-head-row">
            <div className="stat-label">Total Alerts</div>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
              <path d="M13.73 21a2 2 0 01-3.46 0" />
            </svg>
          </div>
          <div className="stat-value">
            <CountUp value={total} />
          </div>
          <div className="kpi-sub">
            {total === 0 ? 'No alerts recorded yet' : 'View all recorded detections →'}
          </div>
        </Link>

        <Link to="/alerts?sev=Critical" className="card kpi-card kpi-link">
          <div className="kpi-head-row">
            <div className="stat-label">Critical Alerts</div>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          </div>
          <div className="stat-value" style={{ color: critical > 0 ? 'var(--danger)' : 'var(--text)' }}>
            <CountUp value={critical} />
          </div>
          <div className="kpi-sub">
            {critical === 0 ? 'No critical threats' : 'Filter critical threats →'}
          </div>
        </Link>

        <Link to="/alerts" className="card kpi-card kpi-link">
          <div className="kpi-head-row">
            <div className="stat-label">Last Hour</div>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="9" />
              <polyline points="12 7 12 12 15 15" />
            </svg>
          </div>
          <div className="stat-value">
            <CountUp value={lastHourCount} />
          </div>
          <div className="kpi-sub">
            {lastHourCount === 0 ? 'Quiet in the last 60 minutes' : 'Alerts in the last 60 minutes'}
          </div>
        </Link>

        <Link
          to={topRaw ? `/alerts?type=${encodeURIComponent(topRaw)}` : '/alerts'}
          className="card kpi-card kpi-link"
        >
          <div className="kpi-head-row">
            <div className="stat-label">Most Common Alert</div>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
          </div>
          <div className="stat-value" style={{ fontSize: 18, lineHeight: 1.3 }}>
            {topPlain}
          </div>
          <div className="kpi-sub">
            {types[0]
              ? `${types[0][0]} · ${types[0][1].toLocaleString()} (${Math.round((types[0][1] / Math.max(1, total)) * 100)}%)`
              : 'No detections yet'}
          </div>
        </Link>
      </section>

      {/* 3. ALERTS-PER-HOUR CHART CARD */}
      <section className="card">
        <div className="band-head">
          <div>
            <div className="stat-label">Alerts per hour (last 12 hours)</div>
            <p className="band-sub">Hourly activity based on recent detections.</p>
          </div>
          {hoverIdx !== null && hourBars[hoverIdx] ? (
            <span className="badge mono" style={{ color: 'var(--accent)', background: 'var(--accent-soft)' }}>
              {hourBars[hoverIdx].label} · {hourBars[hoverIdx].n} {hourBars[hoverIdx].n === 1 ? 'alert' : 'alerts'}
            </span>
          ) : (
            <span className="badge mono">
              {totalInChart} in last 12h
            </span>
          )}
        </div>

        <div className="dash-hour-chart">
          <svg
            viewBox="0 0 600 180"
            className="dash-hour-svg"
            role="img"
            aria-label="Alerts per hour over the last 12 hours"
            onMouseLeave={() => setHoverIdx(null)}
          >
            {[0, 0.5, 1].map((g) => {
              const yLine = 146 - g * 124;
              const tickVal = Math.round(maxHour * g);
              return (
                <g key={g}>
                  <line
                    x1="34"
                    x2="588"
                    y1={yLine}
                    y2={yLine}
                    stroke={g === 0 ? 'var(--border)' : 'var(--divider)'}
                    strokeWidth="1"
                  />
                  <text
                    x="26"
                    y={yLine + 4}
                    textAnchor="end"
                    fill="var(--text-2)"
                    fontSize="11"
                  >
                    {tickVal}
                  </text>
                </g>
              );
            })}
            {hourBars.map((b, i) => {
              const slotW = 550 / hourBars.length;
              const barW = Math.max(16, slotW - 14);
              const x = 36 + i * slotW + (slotW - barW) / 2;
              const h = b.n > 0 ? Math.max(6, (b.n / maxHour) * 124) : 2;
              const y = 146 - h;
              const isHover = hoverIdx === i;
              return (
                <g
                  key={b.hour}
                  onMouseEnter={() => setHoverIdx(i)}
                  style={{ cursor: 'pointer' }}
                >
                  <rect x={36 + i * slotW} y="10" width={slotW} height="160" fill="transparent" />
                  <rect
                    x={x}
                    y={y}
                    width={barW}
                    height={h}
                    rx="4"
                    fill={b.n > 0 ? 'var(--accent)' : 'var(--surface-2)'}
                    opacity={isHover ? 1 : b.n > 0 ? 0.85 : 0.7}
                  />
                  {i % 2 === 0 && (
                    <text
                      x={x + barW / 2}
                      y="168"
                      textAnchor="middle"
                      fill="var(--text-2)"
                      fontSize="12"
                    >
                      {b.label}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
      </section>

      {/* 4. RECENT ALERTS CARD (divider-separated rows) */}
      <section className="card">
        <div className="band-head">
          <div>
            <div className="stat-label">Recent Alerts</div>
            <p className="band-sub">Click any row for plain-English details and next steps.</p>
          </div>
          <Link to="/alerts" className="view-all">View all alerts →</Link>
        </div>

        {alerts.length === 0 ? (
          <Empty title="No alerts yet" note="Detections from your sensor will appear here automatically." />
        ) : (
          <div className="dash-recent-list">
            {alerts.slice(0, 8).map((a) => {
              const sev = severity(a.type);
              const isOpen = openId === a.id;
              const isFresh = freshIds.has(a.id);
              const adv = getAdvice(a.type);
              const friendly = plainName(a.type, a);
              const showTech = friendly.toLowerCase() !== String(a.type || '').toLowerCase();
              return (
                <Fragment key={a.id}>
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={() => setOpenId(isOpen ? null : a.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setOpenId(isOpen ? null : a.id);
                      }
                    }}
                    className={'dash-recent-row' + (isFresh ? ' row-flash' : '')}
                  >
                    <SeverityBadge level={sev} />
                    <div style={{ minWidth: 0 }}>
                      <span className="alert-plain-title">{friendly}</span>
                      {showTech && <span className="alert-tech-sub">{a.type}</span>}
                    </div>
                    <span className="dash-recent-ip mono">
                      {a.src} → {a.dst}{a.dport && a.dport !== '-' ? ':' + a.dport : ''}
                    </span>
                    <span className="dash-recent-time mono" title={formatAbsoluteTime(a.time)}>
                      {timeAgo(a.time)}
                    </span>
                    <span className="alerts-row-action mono">
                      {isOpen ? 'Hide' : 'Details ›'}
                    </span>
                  </div>

                  {isOpen && (
                    <div className="dash-recent-expand">
                      <div className="dash-advice-grid">
                        <div>
                          <small className="mono" style={{ color: 'var(--text-2)' }}>WHAT HAPPENED</small>
                          <p style={{ marginTop: 4 }}>{adv.what}</p>
                        </div>
                        <div>
                          <small className="mono" style={{ color: 'var(--text-2)' }}>WHY IT MATTERS</small>
                          <p style={{ marginTop: 4 }}>{adv.risk}</p>
                        </div>
                      </div>
                      <div className="dash-advice-actions" style={{ marginTop: 12 }}>
                        <small className="mono" style={{ color: 'var(--text-2)' }}>WHAT TO DO</small>
                        <ul style={{ marginTop: 4, paddingLeft: 18 }}>
                          {adv.actions.map((act) => <li key={act}>{act}</li>)}
                        </ul>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 10 }}>
                        <Link to={`/assistant?alert=${a.id}`} onClick={(e) => e.stopPropagation()} style={{ fontWeight: 600 }}>
                          Explain with AI →
                        </Link>
                      </div>
                    </div>
                  )}
                </Fragment>
              );
            })}
          </div>
        )}
      </section>

      <BlockedIpsSection compact id="dashboard-blocked-ips" />

      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <Link to="/analytics" className="view-all">See full history in Analytics →</Link>
      </div>
    </div>
  );
}
