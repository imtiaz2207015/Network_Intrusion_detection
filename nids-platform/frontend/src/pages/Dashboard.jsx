import { useState, useEffect, useRef, Fragment } from 'react';
import { Link } from 'react-router-dom';
import { usePolling, severity, sevColor, SEV_RANK, getAdvice } from '../utils';
import { alertsApi } from '../api';
import { useAuth } from '../AuthContext';
import { CountUp, Skeleton, ErrorBox, Empty } from '../ui';
import { timeAgo, humanAge, formatTimestamp, formatAbsoluteTime } from '../format';
import { BlockedIpsSection } from '../BlockedIps';
import { SENSOR_OFFLINE_GUIDE } from '../helpText';

function parseTimeMs(t) {
  if (!t) return NaN;
  const s = String(t).trim().replace(' ', 'T');
  const ms = Date.parse(s.endsWith('Z') ? s : s + 'Z');
  return isNaN(ms) ? Date.parse(s) : ms;
}

function buckets(alerts) {
  const nowMin = Math.floor(Date.now() / 60000);
  const recentMins = alerts
    .map((a) => Math.floor(parseTimeMs(a.time) / 60000))
    .filter((m) => !isNaN(m) && m >= nowMin - 14 && m <= nowMin + 1);
  if (!recentMins.length) return [];
  const out = [];
  for (let m = nowMin - 14; m <= nowMin; m++) {
    out.push({
      label: new Date(m * 60000).toISOString().slice(11, 16),
      n: recentMins.filter((x) => x === m).length,
    });
  }
  return out;
}

function greeting() {
  const h = new Date().getHours();
  if (h >= 5 && h < 12) return 'Good morning';
  if (h >= 12 && h < 17) return 'Good afternoon';
  if (h >= 17 && h < 21) return 'Good evening';
  return 'Good night';
}

function TopologyGraph({ alerts, sensorHost, sensorOnline }) {
  if (!alerts || alerts.length === 0) {
    return (
      <Empty
        icon="🕸️"
        title="No active flow topology"
        note="Attacker → Sensor → Victim paths will appear as soon as traffic is flagged."
      />
    );
  }

  const now = Date.now();
  const recentFiveMin = alerts.filter((a) => {
    const ms = parseTimeMs(a.time);
    return !isNaN(ms) && now - ms <= 5 * 60 * 1000;
  });

  // Also determine latest 5-minute window in dataset so animated dots work on recorded streams
  const validMs = alerts.map((a) => parseTimeMs(a.time)).filter((m) => !isNaN(m));
  const latestMs = validMs.length ? Math.max(...validMs) : now;
  const activeWindowAlerts = recentFiveMin.length > 0
    ? recentFiveMin
    : alerts.filter((a) => {
        const ms = parseTimeMs(a.time);
        return !isNaN(ms) && latestMs - ms <= 5 * 60 * 1000;
      });

  const activePairs = new Set(
    activeWindowAlerts.map((a) => {
      const rawSrc = a.src ? String(a.src).trim().split(':')[0] : 'unknown';
      const rawDst = a.dst && a.dst !== '-' ? String(a.dst).trim().split(':')[0] : '10.0.0.5';
      return `${rawSrc}->${rawDst}`;
    })
  );

  // Group top 5 attacker IPs and top 5 victim IPs (grouped strictly by host IP)
  const srcMap = new Map();
  const dstMap = new Map();

  for (const a of alerts.slice(0, 80)) {
    const rawSrc = a.src ? String(a.src).trim() : 'unknown';
    const src = rawSrc.includes(':') ? rawSrc.split(':')[0] : rawSrc;

    const rawDst = a.dst && a.dst !== '-' ? String(a.dst).trim() : '10.0.0.5';
    const [dstIpPart, inlinePort] = rawDst.includes(':') ? rawDst.split(':') : [rawDst, ''];
    const dst = dstIpPart || '10.0.0.5';
    const portVal = (a.dport && a.dport !== '-' ? String(a.dport).trim() : '') || inlinePort;

    const sev = severity(a.type);

    if (!srcMap.has(src)) {
      srcMap.set(src, { ip: src, count: 0, sev, type: a.type, time: a.time, active: false });
    }
    const sEntry = srcMap.get(src);
    sEntry.count += 1;
    if (SEV_RANK[sev] > SEV_RANK[sEntry.sev]) sEntry.sev = sev;
    if (activePairs.has(`${src}->${dst}`)) sEntry.active = true;

    if (!dstMap.has(dst)) {
      dstMap.set(dst, {
        ip: dst,
        ports: new Set(),
        count: 0,
        sev,
        time: a.time,
        active: false,
      });
    }
    const dEntry = dstMap.get(dst);
    if (portVal && portVal !== '-') dEntry.ports.add(portVal);
    dEntry.count += 1;
    if (SEV_RANK[sev] > SEV_RANK[dEntry.sev]) dEntry.sev = sev;
    if (activePairs.has(`${src}->${dst}`)) dEntry.active = true;
  }

  const attackers = [...srcMap.values()].sort((a, b) => b.count - a.count).slice(0, 5);
  const victims = [...dstMap.values()].sort((a, b) => b.count - a.count).slice(0, 5);

  const W = 960;
  const H = 368;
  const cx = W / 2;
  const cy = 204;
  const nodeW = 236;
  const nodeH = 50;
  const attX = 16;
  const vicX = W - 16 - nodeW;

  const yPos = (idx, len) => {
    if (len === 1) return cy;
    const span = Math.min(236, (len - 1) * 59);
    const start = cy - span / 2;
    return start + (idx / (len - 1)) * span;
  };

  function formatPortsSummary(portList) {
    if (!portList || portList.length === 0) return 'ports: —';
    if (portList.length === 1) return `ports: ${portList[0]}`;
    const firstTwo = `${portList[0]}, ${portList[1]}`;
    if (portList.length === 2) {
      return firstTwo.length > 12 ? `ports: ${portList[0]}, +1` : `ports: ${firstTwo}`;
    }
    const rest = portList.length - 2;
    const candidate = `ports: ${firstTwo}, +${rest}`;
    if (candidate.length > 18) {
      return `ports: ${portList[0]}, +${portList.length - 1}`;
    }
    return candidate;
  }

  function truncateLabel(str, maxLen = 16) {
    const s = String(str || '');
    return s.length > maxLen ? s.slice(0, maxLen - 1) + '…' : s;
  }

  return (
    <div className="topo-wrap">
      <div className="topo-legend mono">
        <span><i style={{ background: sevColor.Critical }} /> Critical</span>
        <span><i style={{ background: sevColor.High }} /> High</span>
        <span><i style={{ background: sevColor.Medium }} /> Medium</span>
        <span><i style={{ background: sevColor.Low }} /> Low</span>
        {sensorOnline ? (
          <span className="topo-live-note">
            ● Animated packets = {recentFiveMin.length > 0 ? 'last 5m live' : 'latest 5m window'} ({activeWindowAlerts.length} alerts)
          </span>
        ) : (
          <span className="topo-live-note paused">
            Animation paused
          </span>
        )}
      </div>

      <div className="topo-scroll">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="topo-svg"
          role="img"
          aria-label="Attacker to Sensor to Victim network topology graph"
        >
        <defs>
          <radialGradient id="sensorGlow" cx="50%" cy="50%" r="50%">
            <stop
              offset="0%"
              stopColor={sensorOnline ? 'var(--accent)' : 'var(--danger)'}
              stopOpacity={sensorOnline ? '0.28' : '0.18'}
            />
            <stop
              offset="100%"
              stopColor={sensorOnline ? 'var(--accent)' : 'var(--danger)'}
              stopOpacity="0"
            />
          </radialGradient>
        </defs>

        {/* Column Headers */}
        <text x={attX} y="26" className="topo-col-label">ATTACKER SOURCES (PRIVATE LAN)</text>
        <text x={cx} y="26" textAnchor="middle" className="topo-col-label">SENSOR</text>
        <text x={vicX + nodeW} y="26" textAnchor="end" className="topo-col-label">TARGET / VICTIM HOSTS</text>

        {/* Lines: Attacker -> Sensor */}
        {attackers.map((att, i) => {
          const y1 = yPos(i, attackers.length);
          const x1 = attX + nodeW;
          const x2 = cx - 54;
          const y2 = cy;
          const d = `M ${x1} ${y1} C ${x1 + 84} ${y1}, ${x2 - 84} ${y2}, ${x2} ${y2}`;
          const color = sevColor[att.sev];
          return (
            <g key={`att-line-${att.ip}`}>
              <path
                d={d}
                fill="none"
                stroke={color}
                strokeWidth={att.sev === 'Critical' ? 2.4 : 1.8}
                strokeOpacity="0.65"
              />
              {sensorOnline && att.active && (
                <circle r="4" fill={color} className="topo-packet">
                  <animateMotion dur={`${Math.max(1.4, 2.8 - i * 0.25)}s`} repeatCount="indefinite" path={d} />
                </circle>
              )}
            </g>
          );
        })}

        {/* Lines: Sensor -> Victim */}
        {victims.map((vic, i) => {
          const x1 = cx + 54;
          const y1 = cy;
          const x2 = vicX;
          const y2 = yPos(i, victims.length);
          const d = `M ${x1} ${y1} C ${x1 + 84} ${y1}, ${x2 - 84} ${y2}, ${x2} ${y2}`;
          const color = sevColor[vic.sev];
          return (
            <g key={`vic-line-${vic.ip}`}>
              <path
                d={d}
                fill="none"
                stroke={color}
                strokeWidth={vic.sev === 'Critical' ? 2.4 : 1.8}
                strokeOpacity="0.65"
              />
              {sensorOnline && vic.active && (
                <circle r="4" fill={color} className="topo-packet">
                  <animateMotion dur={`${Math.max(1.5, 2.6 - i * 0.2)}s`} repeatCount="indefinite" path={d} />
                </circle>
              )}
            </g>
          );
        })}

        {/* Left Nodes: Attackers */}
        {attackers.map((att, i) => {
          const y = yPos(i, attackers.length);
          const color = sevColor[att.sev];
          const chipLabel = `${att.count} ${att.count === 1 ? 'alert' : 'alerts'}`;
          const chipW = Math.max(58, chipLabel.length * 6.5 + 14);
          const chipH = 22;
          const chipX = nodeW - 10 - chipW;
          const chipY = (nodeH - chipH) / 2;
          const clipId = `att-clip-${i}`;
          return (
            <g key={`att-node-${att.ip}`} transform={`translate(${attX}, ${y - nodeH / 2})`}>
              <title>{`${att.ip} · ${att.type} · ${chipLabel} · ${formatTimestamp(att.time)}`}</title>
              <clipPath id={clipId}>
                <rect x="26" y="4" width={Math.max(60, chipX - 32)} height={nodeH - 8} />
              </clipPath>
              <rect
                width={nodeW}
                height={nodeH}
                rx="10"
                fill="var(--surface-2)"
                stroke={color}
                strokeWidth="1.5"
              />
              <circle cx="15" cy={nodeH / 2} r="4.5" fill={color} />
              <g clipPath={`url(#${clipId})`}>
                <text x="28" y="21" className="topo-ip">{att.ip}</text>
                <text x="28" y="38" className="topo-sub">
                  {truncateLabel(att.type, 16)}
                </text>
              </g>
              <rect
                x={chipX}
                y={chipY}
                width={chipW}
                height={chipH}
                rx="6"
                className="topo-chip-rect"
              />
              <text
                x={chipX + chipW / 2}
                y={chipY + 14.5}
                textAnchor="middle"
                className="topo-chip-text"
              >
                {chipLabel}
              </text>
            </g>
          );
        })}

        {/* Center Node: Sensor */}
        <g transform={`translate(${cx}, ${cy})`}>
          <circle r="60" fill="url(#sensorGlow)" />
          {sensorOnline && (
            <circle
              r="46"
              fill="none"
              stroke="var(--ok)"
              strokeWidth="1.5"
              className="topo-ping-ring"
            />
          )}
          <circle
            r="46"
            fill="var(--surface-2)"
            stroke={sensorOnline ? 'var(--accent)' : 'var(--danger)'}
            strokeWidth="2"
          />
          {sensorOnline && (
            <circle
              r="52"
              fill="none"
              stroke="var(--accent-border)"
              strokeWidth="1.2"
              strokeDasharray="6 4"
              className="topo-ring-spin"
            />
          )}
          <text
            y="-4"
            textAnchor="middle"
            className={'topo-sensor-title' + (sensorOnline ? '' : ' offline')}
          >
            {sensorOnline ? 'SENSOR' : 'OFFLINE'}
          </text>
          <text y="13" textAnchor="middle" className="topo-sensor-sub">
            {(sensorHost || 'rpi-nids').slice(0, 12)}
          </text>
        </g>

        {/* Right Nodes: Victims */}
        {victims.map((vic, i) => {
          const y = yPos(i, victims.length);
          const color = sevColor[vic.sev];
          const portList = [...vic.ports];
          const fullPortsLabel = portList.length > 0 ? `ports: ${portList.join(', ')}` : 'ports: —';
          const shortPortsLabel = formatPortsSummary(portList);
          const chipLabel = `${vic.count} ${vic.count === 1 ? 'hit' : 'hits'}`;
          const chipW = Math.max(52, chipLabel.length * 6.5 + 14);
          const chipH = 22;
          const chipX = nodeW - 10 - chipW;
          const chipY = (nodeH - chipH) / 2;
          const clipId = `vic-clip-${i}`;
          return (
            <g key={`vic-node-${vic.ip}`} transform={`translate(${vicX}, ${y - nodeH / 2})`}>
              <title>{`${vic.ip} · ${fullPortsLabel} · ${chipLabel} · ${formatTimestamp(vic.time)}`}</title>
              <clipPath id={clipId}>
                <rect x="26" y="4" width={Math.max(60, chipX - 32)} height={nodeH - 8} />
              </clipPath>
              <rect
                width={nodeW}
                height={nodeH}
                rx="10"
                fill="var(--surface-2)"
                stroke={color}
                strokeWidth="1.5"
              />
              <circle cx="15" cy={nodeH / 2} r="4.5" fill={color} />
              <g clipPath={`url(#${clipId})`}>
                <text x="28" y="21" className="topo-ip">
                  {vic.ip}
                </text>
                <text x="28" y="38" className="topo-sub">
                  {shortPortsLabel}
                </text>
              </g>
              <rect
                x={chipX}
                y={chipY}
                width={chipW}
                height={chipH}
                rx="6"
                className="topo-chip-rect"
              />
              <text
                x={chipX + chipW / 2}
                y={chipY + 14.5}
                textAnchor="middle"
                className="topo-chip-text"
              >
                {chipLabel}
              </text>
            </g>
          );
        })}
        </svg>
      </div>
    </div>
  );
}

function AttackTypeDonut({ types, total }) {
  if (!types.length || !total) {
    return (
      <Empty
        title="No attack distribution yet"
        note="All-time attack-type proportions will appear here once detections are recorded."
      />
    );
  }

  const r = 66;
  const c = 2 * Math.PI * r;
  let offset = 0;

  const slices = types.map(([label, n]) => {
    const sev = severity(label);
    const color = sevColor[sev] || 'var(--muted)';
    const len = (n / Math.max(1, total)) * c;
    const item = { label, n, color, len, offset, sev };
    offset += len;
    return item;
  });

  return (
    <div className="dash-donut-wrap">
      <svg viewBox="0 0 180 180" className="dash-donut-svg">
        <circle cx="90" cy="90" r={r} fill="none" stroke="var(--surface-2)" strokeWidth="22" />
        {slices.map((s) => (
          <circle
            key={s.label}
            cx="90"
            cy="90"
            r={r}
            fill="none"
            stroke={s.color}
            strokeWidth="22"
            strokeDasharray={`${s.len} ${c - s.len}`}
            strokeDashoffset={-s.offset}
            transform="rotate(-90 90 90)"
          >
            <title>{`${s.label}: ${s.n} (${((s.n / Math.max(1, total)) * 100).toFixed(1)}%)`}</title>
          </circle>
        ))}
        <text x="90" y="86" textAnchor="middle" fill="var(--text)" fontSize="24" fontWeight="700" className="mono">
          {total}
        </text>
        <text x="90" y="105" textAnchor="middle" fill="var(--muted)" fontSize="11">
          total alerts
        </text>
      </svg>

      <div className="dash-donut-legend">
        {slices.map((s) => {
          const share = ((s.n / Math.max(1, total)) * 100).toFixed(1);
          return (
            <div key={s.label} className="dash-donut-row">
              <span className="dash-donut-dot" style={{ background: s.color }} />
              <span className="dash-donut-name">{s.label}</span>
              <span className="mono dash-donut-val">{s.n}</span>
              <span className="mono dash-donut-pct">{share}%</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { user, token } = useAuth();
  const stats = usePolling('/stats');
  const recent = usePolling('/?limit=200');
  const sensor = usePolling('/sensor', 5000);

  const [openId, setOpenId] = useState(null);
  const [freshIds, setFreshIds] = useState(new Set());
  const [critPulse, setCritPulse] = useState(false);
  const [hoverIdx, setHoverIdx] = useState(null);
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

  // Detect newly arrived alerts for green row flash & Critical card red pulse
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

    const hasNewCrit = arrived.some((a) => severity(a.type) === 'Critical');
    if (hasNewCrit) setCritPulse(true);

    const timer = setTimeout(() => {
      setFreshIds(new Set());
      setCritPulse(false);
    }, 2400);
    return () => clearTimeout(timer);
  }, [recent.data]);

  if (stats.error) return <ErrorBox message={stats.error} />;
  if (!stats.data || !recent.data) {
    return (
      <div className="dash-bands">
        <Skeleton h={76} r={16} />
        <div className="grid">
          {[0, 1, 2, 3].map((i) => <Skeleton key={i} h={108} r={16} />)}
        </div>
        <Skeleton h={310} r={16} />
        <Skeleton h={320} r={16} />
        <div className="dash-trend-grid">
          <Skeleton h={240} r={16} />
          <Skeleton h={240} r={16} />
        </div>
      </div>
    );
  }

  const { total, counts } = stats.data;
  const alerts = recent.data.alerts || [];
  const types = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const critical = types
    .filter(([t]) => severity(t) === 'Critical')
    .reduce((s, [, n]) => s + n, 0);

  // Last hour alerts count
  const now = Date.now();
  const lastHourCount = alerts.filter((a) => {
    const ms = parseTimeMs(a.time);
    return !isNaN(ms) && now - ms <= 3600 * 1000;
  }).length;

  const sData = manualSensor || sensor.data;
  const sensorOnline = !!(sData && sData.online);
  const sensorSeen = !!(sData && sData.seen);
  const bars = buckets(alerts);
  const maxBar = Math.max(1, ...bars.map((b) => b.n));

  // Sparkline / Area chart coordinates
  const W = 560;
  const H = 165;
  const pts = bars.map((b, i) => [
    (i / Math.max(1, bars.length - 1)) * (W - 24) + 12,
    H - (b.n / maxBar) * (H - 32) - 14,
  ]);
  const line = pts.map((p) => p.join(',')).join(' ');
  const area = pts.length ? `${pts[0][0]},${H} ${line} ${pts[pts.length - 1][0]},${H}` : '';

  return (
    <div className="dash-bands">
      {/* BAND A: TRUST BAND */}
      <section className={'card trust-band' + (sensorOnline ? ' online' : ' offline')}>
        <div className="trust-left">
          <div className={'trust-radar' + (sensorOnline ? ' online' : ' offline')}>
            <span className="trust-radar-core" />
            <span className="trust-radar-ring" />
          </div>
          <div>
            <div className="trust-title-row">
              <span className="trust-status-badge mono">
                {sensorOnline ? 'PROTECTED · SENSOR ONLINE' : sensorSeen ? 'SENSOR OFFLINE' : 'SENSOR NOT CONNECTED'}
              </span>
              <span className="mono trust-host">
                {sData?.host ? `Device: ${sData.host}` : 'Raspberry Pi Network Sensor'}
              </span>
            </div>
            <p className="trust-sub">
              {greeting()}, <b>{user.username}</b> ·{' '}
              {sensorOnline
                ? `Your network is being monitored live (${(sData.packets || 0).toLocaleString()} packets checked).`
                : sensorSeen
                  ? 'Sensor disconnected. Plug in your sensor device to resume protection.'
                  : 'Your sensor box is currently turned off or disconnected from Wi-Fi.'}
            </p>
          </div>
        </div>

        <div className="trust-right">
          <div className="trust-metric mono">
            <small>LAST SEEN</small>
            <b>{sensorSeen ? humanAge(sData.age) : '—'}</b>
          </div>
          <div className="trust-metric mono">
            <small>PACKETS</small>
            <b>{sensorSeen ? (sData.packets || 0).toLocaleString() : '0'}</b>
          </div>
          {!sensorOnline ? (
            <button
              type="button"
              className="btn sm"
              onClick={toggleSensorGuide}
            >
              {showSensorGuide ? 'Hide steps' : 'Show steps'}
            </button>
          ) : (
            <span className="live">
              <span className="live-dot" />
              LIVE
            </span>
          )}
        </div>
      </section>

      {!sensorOnline && showSensorGuide && (
        <section className="card dash-sensor-guide">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div className="stat-label" style={{ marginBottom: 4 }}>{SENSOR_OFFLINE_GUIDE.title}</div>
              <p className="band-sub">
                {SENSOR_OFFLINE_GUIDE.subtitle}
              </p>
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
              <Link to="/help#sensor-offline" className="btn ghost sm">More Help</Link>
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

      {/* BAND B: STAT CARDS */}
      <section className="grid dash-kpis">
        <div className="card kpi-card">
          <div className="stat-label">Total Alerts</div>
          <div className="stat-value" style={{ color: total === 0 ? 'var(--muted)' : 'var(--accent)' }}>
            <CountUp value={total} />
          </div>
          <div className="kpi-sub mono">
            {total === 0 ? 'No alerts recorded yet' : 'All recorded detections'}
          </div>
        </div>

        <div className={'card kpi-card' + (critPulse ? ' crit-pulse' : '')} style={{ borderColor: critical > 0 ? 'var(--danger-border)' : undefined }}>
          <div className="stat-label" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Critical Alerts</span>
            {critical > 0 && <span className="kpi-crit-dot" />}
          </div>
          <div className="stat-value" style={{ color: critical === 0 ? 'var(--muted)' : 'var(--danger)' }}>
            <CountUp value={critical} />
          </div>
          <div className="kpi-sub mono">
            {critical === 0 ? 'No critical alerts' : 'DoS / SYN Flood priority'}
          </div>
        </div>

        <div className="card kpi-card">
          <div className="stat-label">Last Hour</div>
          <div className="stat-value" style={{ color: lastHourCount === 0 ? 'var(--muted)' : 'var(--warn)' }}>
            <CountUp value={lastHourCount} />
          </div>
          <div className="kpi-sub mono">
            {lastHourCount === 0 ? 'No alerts in the last hour' : 'In the last 60 minutes (recent 200)'}
          </div>
        </div>

        <div className="card kpi-card">
          <div className="stat-label">Top Attack Type</div>
          <div className="stat-value" style={{ fontSize: 22, color: types[0] ? 'var(--accent-2)' : 'var(--muted)' }}>
            {types[0] ? types[0][0] : '—'}
          </div>
          <div className="kpi-sub mono">
            {types[0] ? `${types[0][1].toLocaleString()} alerts (${Math.round((types[0][1] / Math.max(1, total)) * 100)}%)` : 'No detections yet'}
          </div>
        </div>
      </section>

      {/* BAND C: LIVE ALERT FEED (What to work on now) */}
      <section className="card">
        <div className="band-head">
          <div>
            <div className="stat-label">Live Alert Feed</div>
            <div className="dash-feed-sub-wrap">
              <p className="band-sub">
                Click any row to inspect plain-English mitigation advice.
                {sensorOnline ? ' New detections slide in automatically.' : ''}
              </p>
              {!sensorOnline && (
                <span className="dash-paused-chip mono">
                  Live updates paused
                </span>
              )}
            </div>
          </div>
          <Link to="/alerts" className="view-all">Open full triage table →</Link>
        </div>

        {alerts.length === 0 ? (
          <Empty title="No alerts yet" note="New detections from the sensor will stream here in real time." />
        ) : (
          <>
            <div className="table-scroll-wrap dash-feed-desktop">
              <table className="table dash-feed-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Attack Type</th>
                    <th>Source → Target</th>
                    <th>Details</th>
                    <th style={{ width: 92, textAlign: 'right' }} aria-label="Details" />
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 8).map((a) => {
                    const sev = severity(a.type);
                    const isOpen = openId === a.id;
                    const isFresh = freshIds.has(a.id);
                    const adv = getAdvice(a.type);
                    return (
                      <Fragment key={a.id}>
                        <tr
                          onClick={() => setOpenId(isOpen ? null : a.id)}
                          className={'alerts-row ' + (isFresh ? 'row-flash ' : '') + (isOpen ? 'is-open row-expanded' : '')}
                          style={{ '--row-sev': sevColor[sev], cursor: 'pointer' }}
                        >
                          <td
                            title={formatAbsoluteTime(a.time)}
                            className="mono alerts-sev-bar-cell"
                            style={{ whiteSpace: 'nowrap' }}
                          >
                            {timeAgo(a.time)}
                          </td>
                          <td>
                            <span className={'sev-chip ' + sev.toLowerCase()}>{sev}</span>
                          </td>
                          <td style={{ fontWeight: 600 }}>{a.type}</td>
                          <td className="mono">
                            {a.src} → {a.dst}{a.dport && a.dport !== '-' ? ':' + a.dport : ''}
                          </td>
                          <td style={{ color: 'var(--muted)' }}>{a.detail || '—'}</td>
                          <td className="alerts-expand-cell">
                            <span className={'alerts-row-action mono' + (isOpen ? ' open' : '')}>
                              {isOpen ? 'Hide' : 'Details ›'}
                            </span>
                          </td>
                        </tr>
                        {isOpen && (
                          <tr>
                            <td colSpan={6} className="dash-advice-cell">
                              <div className="dash-advice-box">
                                <div className="dash-advice-grid">
                                  <div>
                                    <small className="mono">WHAT HAPPENED</small>
                                    <p>{adv.what}</p>
                                  </div>
                                  <div>
                                    <small className="mono">RISK IMPACT</small>
                                    <p>{adv.risk}</p>
                                  </div>
                                </div>
                                <div className="dash-advice-actions">
                                  <small className="mono">RECOMMENDED MITIGATION</small>
                                  <ul>
                                    {adv.actions.map((act) => <li key={act}>{act}</li>)}
                                  </ul>
                                </div>
                                <div className="dash-advice-foot mono" style={{ justifyContent: 'flex-end' }}>
                                  <Link to="/assistant" onClick={(e) => e.stopPropagation()}>Ask AI Assistant →</Link>
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

            <div className="alerts-mobile-list dash-feed-mobile">
              {alerts.slice(0, 8).map((a) => {
                const sev = severity(a.type);
                const isOpen = openId === a.id;
                const isFresh = freshIds.has(a.id);
                const adv = getAdvice(a.type);
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
                      </div>
                      <span
                        className="mono"
                        title={formatAbsoluteTime(a.time)}
                        style={{ fontSize: 11.5, color: 'var(--muted)' }}
                      >
                        {timeAgo(a.time)}
                      </span>
                    </div>

                    <div className="alerts-mcard-ips mono">
                      <span>Src: <b>{a.src}</b></span>
                      <span>→</span>
                      <span>Dst: {a.dst}{a.dport && a.dport !== '-' ? ':' + a.dport : ''}</span>
                    </div>

                    {a.detail && (
                      <div className="alerts-mcard-detail">{a.detail}</div>
                    )}

                    <div className="alerts-mcard-actions">
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
                          <small className="mono">RECOMMENDED MITIGATION</small>
                          <ul className="alerts-mit-list">
                            {adv.actions.map((act) => <li key={act}>{act}</li>)}
                          </ul>
                        </div>
                        <div className="dash-advice-foot mono" style={{ justifyContent: 'flex-end' }}>
                          <Link to="/assistant">Ask AI Assistant →</Link>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </section>

      {/* BLOCKED IPS CARD (under Live Alert Feed) */}
      <BlockedIpsSection compact id="dashboard-blocked-ips" />

      {/* BAND D: ATTACKER -> SENSOR -> VICTIM TOPOLOGY GRAPH (Pure SVG) */}
      <section className="card">
        <div className="band-head">
          <div>
            <div className="stat-label">Attacker → Sensor → Victim Topology</div>
            <p className="band-sub">
              {sensorOnline
                ? 'Live private-network (10.x.x.x) intrusion paths through the sensor, colored by severity.'
                : 'Snapshot of recent history. The sensor is offline.'}
            </p>
          </div>
          <span className="badge mono">{alerts.length} recent flows</span>
        </div>
        <TopologyGraph
          alerts={alerts}
          sensorHost={sData?.host}
          sensorOnline={sensorOnline}
        />
      </section>

      {/* BAND E: TRENDS (Sparkline Area Chart + Attack-Type Donut) */}
      <section className="dash-trend-grid">
        <div className="card">
          <div className="band-head">
            <div>
              <div className="stat-label">Alerts per minute · last 15 min (live)</div>
              <p className="band-sub">Burst cadence across the latest 15 minutes of detection activity.</p>
            </div>
            {hoverIdx !== null && bars[hoverIdx] && (
              <span className="badge mono" style={{ color: 'var(--accent)', borderColor: 'var(--accent-border)' }}>
                {bars[hoverIdx].label} UTC · {bars[hoverIdx].n} alerts
              </span>
            )}
          </div>

          {bars.length === 0 ? (
            <Empty
              title="No detections in the last 15 minutes"
              note="Per-minute burst cadence will plot here automatically when new alerts arrive."
            />
          ) : (
            <div>
              <svg
                viewBox={`0 0 ${W} ${H}`}
                style={{ width: '100%', height: 185, overflow: 'visible' }}
                onMouseLeave={() => setHoverIdx(null)}
              >
                <defs>
                  <linearGradient id="dashAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.4" />
                    <stop offset="100%" stopColor="var(--accent-2)" stopOpacity="0.0" />
                  </linearGradient>
                </defs>

                {/* Horizontal guide lines */}
                {[0.25, 0.5, 0.75].map((g) => (
                  <line
                    key={g}
                    x1="12"
                    x2={W - 12}
                    y1={H * g}
                    y2={H * g}
                    stroke="var(--border)"
                    strokeDasharray="4 4"
                    strokeWidth="1"
                  />
                ))}

                <polygon points={area} fill="url(#dashAreaGrad)" />
                <polyline
                  points={line}
                  fill="none"
                  stroke="var(--accent)"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />

                {pts.map(([x, y], i) => (
                  <g key={i} onMouseEnter={() => setHoverIdx(i)} style={{ cursor: 'pointer' }}>
                    <rect x={x - 14} y="0" width="28" height={H} fill="transparent" />
                    <circle
                      cx={x}
                      cy={y}
                      r={hoverIdx === i ? 5.5 : 3}
                      fill={hoverIdx === i ? 'var(--accent)' : 'var(--surface)'}
                      stroke="var(--accent)"
                      strokeWidth="2"
                    />
                  </g>
                ))}
              </svg>
              <div className="mono" style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>
                <span>{bars[0]?.label}</span>
                <span>Peak: {maxBar}/min</span>
                <span>{bars[bars.length - 1]?.label}</span>
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="band-head">
            <div>
              <div className="stat-label">Attack types · recent alerts</div>
              <p className="band-sub">
                {bars.length === 0 && types.length > 0
                  ? 'All-time breakdown across recorded detections, colored by threat severity.'
                  : 'Proportional breakdown colored by threat severity (red / orange / yellow).'}
              </p>
            </div>
          </div>
          <AttackTypeDonut types={types} total={total} />
        </div>
      </section>

      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: -8 }}>
        <Link to="/analytics" className="view-all">See full history in Analytics →</Link>
      </div>
    </div>
  );
}
