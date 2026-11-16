import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { alertsApi } from '../api';
import { severity } from '../utils';
import { ThemeToggle } from '../ui';
import metrics from '../modelMetrics.json';
import '../landing.css';

const DEMO_ALERTS = [
  { id: 'd1', type: 'DoS/SYN Flood', src: '203.0.113.23', dst: '192.0.2.5', dport: '80', time: 'just now', detail: '412 SYN pkt/5s · Rule + RF Binary23' },
  { id: 'd2', type: 'PortScan', src: '203.0.113.17', dst: '192.0.2.5', dport: '1-1024', time: '4s ago', detail: '38 distinct ports probed in 3.2s' },
  { id: 'd3', type: 'BruteForce', src: '203.0.113.41', dst: '192.0.2.5', dport: '22', time: '11s ago', detail: '19 rapid SSH auth flows detected' },
  { id: 'd4', type: 'UDP Flood', src: '203.0.113.88', dst: '192.0.2.5', dport: '53', time: '19s ago', detail: '1,240 UDP pkt/s volumetric spike' },
  { id: 'd5', type: 'ICMP Flood', src: '203.0.113.62', dst: '192.0.2.5', dport: '-', time: '27s ago', detail: '680 ICMP echo requests/5s' },
];

const PIPELINE = [
  {
    step: '01',
    title: 'Raspberry Pi Sensor',
    tag: 'Scapy Packet Capture',
    desc: 'Sniffs live network interfaces in promiscuous mode, groups packets into bidirectional 5-tuple flows, and extracts 23 real-time statistical features.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="4" y="4" width="16" height="16" rx="3" />
        <rect x="9" y="9" width="6" height="6" />
        <path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3" />
      </svg>
    ),
  },
  {
    step: '02',
    title: 'ML + Rule Engine',
    tag: 'Random Forest + Signatures',
    desc: 'Scores every flow concurrently with deterministic threshold rules and our CICIDS2017 Random Forest models (23-feature live binary + 11-class classifier).',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L2 7l10 5 10-5-10-5z" />
        <path d="M2 17l10 5 10-5" />
        <path d="M2 12l10 5 10-5" />
      </svg>
    ),
  },
  {
    step: '03',
    title: 'Alert Service',
    tag: 'Storage & Severity Triage',
    desc: 'Persists detections with severity grading, tracks live sensor heartbeats, powers real-time analytics, and sends email and browser notifications for Critical alerts.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
        <path d="M13.73 21a2 2 0 01-3.46 0" />
      </svg>
    ),
  },
  {
    step: '04',
    title: 'AI Explanation',
    tag: 'Claude + Built-in Playbooks',
    desc: 'Translates raw network telemetry into plain-English incident summaries, risk verdicts, and step-by-step defensive mitigation checklists.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 3l1.9 5.8a2 2 0 001.3 1.3L21 12l-5.8 1.9a2 2 0 00-1.3 1.3L12 21l-1.9-5.8a2 2 0 00-1.3-1.3L3 12l5.8-1.9a2 2 0 001.3-1.3L12 3z" />
      </svg>
    ),
  },
];

const ATTACK_CARDS = [
  {
    name: 'PortScan',
    sev: 'Medium',
    rule: '≥ 10 distinct dports / window',
    desc: 'Detects horizontal and vertical reconnaissance scans probing open TCP/UDP services before exploitation.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="12" r="3" />
        <path d="M12 3v3M12 18v3M3 12h3M18 12h3" />
      </svg>
    ),
  },
  {
    name: 'DoS / SYN Flood',
    sev: 'Critical',
    rule: '≥ 100 SYN packets / 5s',
    desc: 'Spots half-open TCP handshake floods designed to exhaust server connection tables and starve legitimate clients.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
      </svg>
    ),
  },
  {
    name: 'BruteForce',
    sev: 'High',
    rule: 'Rapid auth attempts (:22, :21, :3389)',
    desc: 'Catches automated credential-stuffing and dictionary bursts against SSH, FTP, RDP, and web login endpoints.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0110 0v4" />
        <circle cx="12" cy="16" r="1.5" />
      </svg>
    ),
  },
  {
    name: 'UDP Flood',
    sev: 'High',
    rule: 'Volumetric UDP packet rate spike',
    desc: 'Identifies high-rate connectionless packet floods targeting DNS, VoIP, or random ephemeral ports to saturate bandwidth.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M2 12h4l3-8 4 16 3-8h6" />
      </svg>
    ),
  },
  {
    name: 'ICMP Flood',
    sev: 'High',
    rule: 'Sustained ICMP Echo burst',
    desc: 'Flags anomalous ping storms and ICMP echo floods aimed at overwhelming interface queues and control-plane CPU.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5M19.1 4.9C23 8.8 23 15.2 19.1 19.1" />
        <circle cx="12" cy="12" r="2" />
      </svg>
    ),
  },
];

const AI_SAMPLES = [
  {
    id: 402,
    type: 'DoS/SYN Flood',
    sev: 'Critical',
    src: '10.0.0.23',
    dst: '10.0.0.5:80',
    time: '19:42:18',
    verdict: '[HIGH] Active TCP SYN flood targeting HTTP service on 10.0.0.5:80.',
    what: 'Host 10.0.0.23 sent 412 TCP SYN packets without completing the 3-way handshake in under 5 seconds, attempting to exhaust the target TCP backlog queue.',
    risk: 'Legitimate users may experience dropped connections or complete HTTP service unavailability if the half-open queue fills up.',
    steps: [
      'Enable TCP SYN cookies on 10.0.0.5 (sysctl -w net.ipv4.tcp_syncookies=1).',
      'Rate-limit inbound SYN packets from 10.0.0.23 at the perimeter firewall.',
      'Mark alert #402 as Investigating and monitor for distributed sources.',
    ],
  },
  {
    id: 398,
    type: 'PortScan',
    sev: 'Medium',
    src: '10.0.0.17',
    dst: '10.0.0.5 (ports 1-1024)',
    time: '19:40:05',
    verdict: '[MEDIUM] Rapid reconnaissance sweep across 38 privileged TCP ports.',
    what: 'Source 10.0.0.17 sequentially probed 38 distinct destination ports on 10.0.0.5 within 3.2 seconds to enumerate listening services.',
    risk: 'Port scanning is typically the reconnaissance phase immediately preceding targeted brute-force or service exploitation.',
    steps: [
      'Block or rate-limit 10.0.0.17 on internal segment firewall rules.',
      'Verify that unused ports on 10.0.0.5 are closed or filtered.',
      'Correlate 10.0.0.17 with subsequent SSH or web login attempts.',
    ],
  },
  {
    id: 391,
    type: 'BruteForce',
    sev: 'High',
    src: '10.0.0.41',
    dst: '10.0.0.5:22',
    time: '19:37:51',
    verdict: '[HIGH] Sustained SSH credential brute-force attack on port 22.',
    what: 'Detected 19 rapid short-lived TCP sessions from 10.0.0.41 to 10.0.0.5:22 consistent with automated password guessing.',
    risk: 'Weak or default credentials on the SSH daemon could grant unauthorized shell access to the host.',
    steps: [
      'Temporarily quarantine source IP 10.0.0.41 via fail2ban or firewall drop rule.',
      'Enforce SSH public-key authentication and disable password login.',
      'Audit /var/log/auth.log on 10.0.0.5 for any successful login after 19:37.',
    ],
  },
];

function ScrollCount({ value, decimals = 0, suffix = '', prefix = '' }) {
  const [n, setN] = useState(0);
  const ref = useRef(null);
  const ran = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) {
      setN(Number(value) || 0);
      return;
    }
    let raf;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !ran.current) {
          ran.current = true;
          const target = Number(value) || 0;
          const start = performance.now();
          const dur = 1100;
          const tick = (now) => {
            const p = Math.min(1, (now - start) / dur);
            const eased = 1 - Math.pow(1 - p, 3);
            setN(target * eased);
            if (p < 1) raf = requestAnimationFrame(tick);
            else setN(target);
          };
          raf = requestAnimationFrame(tick);
          io.disconnect();
        }
      },
      { threshold: 0.25 }
    );
    io.observe(el);
    return () => {
      io.disconnect();
      if (raf) cancelAnimationFrame(raf);
    };
  }, [value]);

  const formatted = decimals > 0
    ? n.toFixed(decimals)
    : Math.round(n).toLocaleString();

  return <span ref={ref}>{prefix}{formatted}{suffix}</span>;
}

export default function Landing() {
  const { token } = useAuth();
  const [menu, setMenu] = useState(false);
  const [liveData, setLiveData] = useState(null);
  const [demoIdx, setDemoIdx] = useState(0);
  const [activeStep, setActiveStep] = useState(0);
  const [aiIdx, setAiIdx] = useState(0);
  const [typedLen, setTypedLen] = useState(0);

  const liveModel = metrics.models.find((m) => m.key === 'binary23') || metrics.models[0];
  const benchModel = metrics.models.find((m) => m.key === 'binary78') || metrics.models[0];
  const multiModel = metrics.models.find((m) => m.key === 'multiclass') || metrics.models[0];
  const bestModel = [...metrics.models].sort((a, b) => b.f1 - a.f1)[0];
  const bestAccModel = [...metrics.models].sort((a, b) => b.accuracy - a.accuracy)[0];
  const bestRecallModel = [...metrics.models].sort((a, b) => b.recall - a.recall)[0];

  // Try fetching real telemetry if logged in; gracefully fall back to labelled demo sample
  useEffect(() => {
    let alive = true;
    async function fetchLive() {
      if (!token) return;
      try {
        const [st, rec, sen] = await Promise.all([
          alertsApi('/stats', { token }),
          alertsApi('/?limit=5', { token }),
          alertsApi('/sensor', { token }),
        ]);
        if (alive && st && rec) {
          setLiveData({ stats: st, alerts: rec.alerts || [], sensor: sen });
        }
      } catch {
        // Fallback to demo preview when unauthenticated or offline
      }
    }
    fetchLive();
    return () => { alive = false; };
  }, [token]);

  // Scroll reveal observer
  useEffect(() => {
    document.title = 'SentinelIQ · Real-Time AI Network Intrusion Detection';
    const els = document.querySelectorAll('.reveal');
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add('show');
          io.unobserve(e.target);
        }
      }),
      { threshold: 0.12 }
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  // Rotate pipeline step & demo feed ticker (pauses when tab is hidden or reduced-motion is on)
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const id = setInterval(() => {
      if (document.hidden) return;
      setActiveStep((s) => (s + 1) % PIPELINE.length);
      setDemoIdx((d) => (d + 1) % DEMO_ALERTS.length);
    }, 2800);
    return () => clearInterval(id);
  }, []);

  // Typing animation for AI Explain Demo
  const currentAi = AI_SAMPLES[aiIdx];
  const fullAiText = `${currentAi.verdict}\n\nWhat happened: ${currentAi.what}\n\nRisk: ${currentAi.risk}`;

  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) {
      setTypedLen(fullAiText.length);
      return;
    }
    setTypedLen(0);
    const id = setInterval(() => {
      if (document.hidden) return;
      setTypedLen((n) => {
        if (n >= fullAiText.length) {
          clearInterval(id);
          return fullAiText.length;
        }
        return n + 3;
      });
    }, 18);
    return () => clearInterval(id);
  }, [aiIdx, fullAiText]);

  const isRealLive = !!(liveData && liveData.alerts && liveData.alerts.length > 0);
  const previewAlerts = isRealLive
    ? liveData.alerts.slice(0, 4)
    : [0, 1, 2, 3].map((offset) => DEMO_ALERTS[(demoIdx + offset) % DEMO_ALERTS.length]);

  const totalAlertsCount = isRealLive ? liveData.stats.total : benchModel.test_rows;
  const sensorOnline = isRealLive ? !!(liveData.sensor && liveData.sensor.online) : true;

  return (
    <div className="lp" id="top">
      {/* 1. Sticky Glass Navbar */}
      <nav className="lp-nav">
        <Link to="/home" className="lp-logo">
          <span className="lp-logo-mark" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
              <circle cx="12" cy="12" r="2.5" fill="currentColor" />
            </svg>
          </span>
          <span>Sentinel<em>IQ</em></span>
        </Link>

        <div className={'lp-links' + (menu ? ' open' : '')} onClick={() => setMenu(false)}>
          <a href="#features">Features</a>
          <a href="#how">How it works</a>
          <a href="#models">Models</a>
          <Link to="/login" className="lp-mob-only">Login</Link>
          <Link to={token ? '/' : '/login'} className="lp-mob-only lp-mob-cta">Open dashboard →</Link>
        </div>

        <div className="lp-right">
          <ThemeToggle />
          <Link to="/login" className="lp-login-link">Login</Link>
          <Link to={token ? '/' : '/login'} className="lp-btn primary sm lp-nav-cta">
            Open dashboard
          </Link>
          <button className="lp-burger" onClick={() => setMenu(!menu)} aria-label="Toggle navigation menu" aria-expanded={menu}>
            {menu ? '✕' : '☰'}
          </button>
        </div>
      </nav>

      {/* 2. Hero with Live Mini-Dashboard Preview */}
      <header className="lp-hero">
        <div className="lp-hero-copy">
          <div className="lp-eyebrow">
            <span className="lp-pulse-dot" />
            DEFENSIVE AI INTRUSION DETECTION · {metrics.dataset} + LIVE SENSOR
          </div>
          <h1>
            Spot Network Intrusions <em>As They Happen</em> — Explained by AI.
          </h1>
          <p>
            SentinelIQ combines a live Raspberry Pi packet sensor, deterministic flood/scan signatures, and a Random Forest classifier reaching {(bestAccModel.accuracy * 100).toFixed(2)}% accuracy on the {metrics.dataset} test set with instant plain-English incident triage.
          </p>
          <div className="lp-btns">
            <Link to={token ? '/' : '/login'} className="lp-btn primary">
              {token ? 'Open Live Dashboard →' : 'Open Dashboard →'}
            </Link>
            <a href="#how" className="lp-btn ghost">
              See How It Works
            </a>
          </div>
          <div className="lp-hero-tags mono">
            <span>✓ {ATTACK_CARDS.length} Live Rule Detectors</span>
            <span>✓ {multiModel.classes.length} ML Attack Classes</span>
            <span>✓ Plain-English AI Explanations</span>
          </div>
        </div>

        {/* Mini Dashboard Preview Window */}
        <div className="lp-preview" aria-label="Dashboard Preview">
          <div className="lp-prev-bar">
            <div className="lp-prev-dots">
              <i /><i /><i />
            </div>
            <div className="lp-prev-url mono">sentineliq.local/dashboard</div>
            <span className={'lp-prev-mode mono ' + (isRealLive ? 'live' : 'demo')}>
              <b /> {isRealLive ? 'LIVE SENSOR STREAM' : 'DEMO SAMPLE PREVIEW'}
            </span>
          </div>

          <div className="lp-prev-body">
            {/* Trust strip inside preview */}
            <div className="lp-prev-trust">
              <div className="lp-prev-sensor">
                <span className="lp-radar-ping" />
                <div>
                  <strong>{sensorOnline ? 'Raspberry Pi Sensor Online' : 'Sensor Standby'}</strong>
                  <small className="mono">
                    {isRealLive && liveData.sensor?.host
                      ? `${liveData.sensor.host} · ${liveData.sensor.packets || 0} pkts`
                      : `eth0 · ${liveModel.n_features} live features · Scapy + RF`}
                  </small>
                </div>
              </div>
              <span className="lp-prev-chip mono">Poll: 5.0s</span>
            </div>

            {/* Mini Stat Cards */}
            <div className="lp-prev-kpis">
              <div className="lp-prev-kpi">
                <small>ACTIVE DETECTIONS</small>
                <b className="mono">{isRealLive ? liveData.stats.total : DEMO_ALERTS.length}</b>
                <span>Rule + ML engine</span>
              </div>
              <div className="lp-prev-kpi crit">
                <small>CRITICAL / HIGH</small>
                <b className="mono">
                  {isRealLive
                    ? previewAlerts.filter((a) => severity(a.type) !== 'Medium').length
                    : DEMO_ALERTS.filter((a) => severity(a.type) !== 'Medium').length}
                </b>
                <span>Immediate review</span>
              </div>
              <div className="lp-prev-kpi">
                <small>RF RECALL · {metrics.dataset} test set</small>
                <b className="mono">{(bestRecallModel.recall * 100).toFixed(2)}%</b>
                <span>{bestRecallModel.n_features}-feature model</span>
              </div>
            </div>

            {/* Mini Live Alert Rows */}
            <div className="lp-prev-feed">
              <div className="lp-prev-feed-head">
                <span>RECENT INTRUSION STREAM</span>
                <span className="mono">SRC → DST</span>
              </div>
              {previewAlerts.map((a, idx) => {
                const sev = severity(a.type);
                return (
                  <div
                    key={`${a.id}-${idx}`}
                    className={'lp-prev-row' + (idx === 0 ? ' flash' : '')}
                  >
                    <span className={'lp-sev ' + sev.toLowerCase()}>{sev}</span>
                    <div className="lp-prev-main">
                      <b>{a.type}</b>
                      <small>{a.detail || 'Flagged by hybrid detector'}</small>
                    </div>
                    <div className="lp-prev-meta mono">
                      <span>{a.src} → {a.dst}{a.dport && a.dport !== '-' ? ':' + a.dport : ''}</span>
                      <small>{a.time}</small>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </header>

      {/* 3. Live Counter Strip (Scroll Count-Up) */}
      <section className="lp-counter-strip reveal" aria-label="Platform Metrics">
        <div className="lp-counter-item">
          <div className="lp-counter-val mono">
            <ScrollCount value={totalAlertsCount} />
          </div>
          <div className="lp-counter-lbl">
            {isRealLive ? 'Live Alerts Recorded' : 'CICIDS2017 Test Flows Verified'}
          </div>
        </div>
        <div className="lp-counter-item">
          <div className="lp-counter-val mono">
            <ScrollCount value={5} suffix=" Rules + " />
            <ScrollCount value={multiModel.classes.length} suffix=" ML" />
          </div>
          <div className="lp-counter-lbl">Attack Types &amp; Signatures Covered</div>
        </div>
        <div className="lp-counter-item">
          <div className="lp-counter-val mono">
            <ScrollCount value={benchModel.accuracy * 100} decimals={2} suffix="%" />
          </div>
          <div className="lp-counter-lbl">Benchmark Random Forest Accuracy</div>
        </div>
        <div className="lp-counter-item">
          <div className="lp-counter-val mono lp-status-online">
            <span className="lp-pulse-dot" />
            {isRealLive ? (sensorOnline ? 'ONLINE' : 'STANDBY') : 'REAL-TIME'}
          </div>
          <div className="lp-counter-lbl">
            {isRealLive ? 'Live Sensor Heartbeat Status' : 'Sub-5s Packet-to-Alert Pipeline'}
          </div>
        </div>
      </section>

      {/* 4. "How It Works" Animated Sequential Pipeline */}
      <section className="lp-sec" id="how">
        <div className="lp-sec-head reveal">
          <span className="lp-kicker mono">ARCHITECTURE PIPELINE</span>
          <h2>How Sentinel<em className="lp-brand-iq">IQ</em> Works</h2>
          <p className="sub">
            Four sequential stages turn raw Ethernet frames into actionable, AI-explained security alerts.
          </p>
        </div>

        <div className="lp-pipe reveal">
          {PIPELINE.map((item, i) => {
            const isActive = activeStep === i;
            return (
              <div
                key={item.step}
                className={'lp-pipe-node' + (isActive ? ' active' : '')}
                onMouseEnter={() => setActiveStep(i)}
                onClick={() => setActiveStep(i)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setActiveStep(i)}
              >
                <div className="lp-pipe-top">
                  <span className="lp-pipe-num mono">{item.step}</span>
                  <div className="lp-pipe-icon">{item.icon}</div>
                  <span className="lp-pipe-tag mono">{item.tag}</span>
                </div>
                <h3>{item.title}</h3>
                <p>{item.desc}</p>
                {i < PIPELINE.length - 1 && (
                  <div className="lp-pipe-connector" aria-hidden="true">
                    <span className="lp-pipe-packet" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* 5. Attack Types Covered (5 Cards with Inline SVGs) */}
      <section className="lp-sec" id="features">
        <div className="lp-sec-head reveal">
          <span className="lp-kicker mono">THREAT COVERAGE</span>
          <h2>5 Real-Time Attack Detectors</h2>
          <p className="sub">
            Hybrid signature rules and flow-level machine learning catch reconnaissance, floods, and credential attacks immediately.
          </p>
        </div>

        <div className="lp-attack-grid">
          {ATTACK_CARDS.map((card, i) => (
            <article
              className="lp-attack-card reveal"
              key={card.name}
              style={{ transitionDelay: `${i * 60}ms` }}
            >
              <div className="lp-attack-top">
                <div className="lp-attack-icon">{card.icon}</div>
                <span className={'lp-sev ' + card.sev.toLowerCase()}>{card.sev}</span>
              </div>
              <h3>{card.name}</h3>
              <p>{card.desc}</p>
              <div className="lp-attack-rule mono">{card.rule}</div>
            </article>
          ))}
        </div>
      </section>

      {/* 6. Interactive AI Explain Demo with Typing Effect */}
      <section className="lp-sec">
        <div className="lp-sec-head reveal">
          <span className="lp-kicker mono">AI SOC ASSISTANT</span>
          <h2>Instant Plain-English Incident Triage</h2>
          <p className="sub">
            Select any sample detection below to watch how the AI Assistant explains what happened, why it matters, and how to mitigate it.
          </p>
        </div>

        <div className="lp-ai-demo reveal">
          <div className="lp-ai-list" role="tablist" aria-label="Sample Alerts">
            <div className="lp-ai-list-head mono">SELECT SAMPLE ALERT</div>
            {AI_SAMPLES.map((s, idx) => (
              <button
                key={s.id}
                role="tab"
                aria-selected={aiIdx === idx}
                className={'lp-ai-tab' + (aiIdx === idx ? ' active' : '')}
                onClick={() => setAiIdx(idx)}
              >
                <div className="lp-ai-tab-top">
                  <span className={'lp-sev ' + s.sev.toLowerCase()}>{s.sev}</span>
                  <span className="mono">#{s.id} · {s.time}</span>
                </div>
                <strong>{s.type}</strong>
                <small className="mono">{s.src} → {s.dst}</small>
              </button>
            ))}
          </div>

          <div className="lp-ai-terminal">
            <div className="lp-ai-term-head">
              <span className="lp-ai-badge mono">✦ Explained by AI Assistant</span>
              <span className="mono" style={{ color: 'var(--muted)', fontSize: 12 }}>
                Alert #{currentAi.id} · {currentAi.src}
              </span>
            </div>

            <pre className="lp-ai-typed mono">
              {fullAiText.slice(0, typedLen)}
              {typedLen < fullAiText.length && <span className="lp-caret" />}
            </pre>

            <div className="lp-ai-steps">
              <div className="lp-ai-steps-title mono">RECOMMENDED DEFENSIVE ACTIONS</div>
              <ol>
                {currentAi.steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </div>
          </div>
        </div>
      </section>

      {/* 7. Model Accuracy Section (Single Summary Card for Highest-F1 Model from src/modelMetrics.json) */}
      <section className="lp-sec" id="models">
        <div className="lp-sec-head reveal">
          <span className="lp-kicker mono">{metrics.dataset} · {metrics.split.toUpperCase()}</span>
          <h2>Measured Machine Learning Performance</h2>
          <p className="sub">
            Evaluated on a held-out {metrics.dataset} test set (offline benchmark).
          </p>
        </div>

        <div className="lp-models-single">
          <div className="lp-model-card featured reveal">
            <div className="lp-model-top">
              <span className="lp-model-tag mono">OFFLINE BENCHMARK · {bestModel.n_features} features</span>
              <span className="mono" style={{ color: 'var(--muted)', fontSize: 12 }}>
                {bestModel.test_rows.toLocaleString()} test rows
              </span>
            </div>
            <h3>{bestModel.title}</h3>
            <p>{bestModel.description}</p>

            <div className="lp-model-metrics">
              <div>
                <small>Accuracy</small>
                <b className="mono">
                  <ScrollCount value={bestModel.accuracy * 100} decimals={2} suffix="%" />
                </b>
              </div>
              <div>
                <small>Precision</small>
                <b className="mono">
                  <ScrollCount value={bestModel.precision * 100} decimals={2} suffix="%" />
                </b>
              </div>
              <div>
                <small>Recall</small>
                <b className="mono">
                  <ScrollCount value={bestModel.recall * 100} decimals={2} suffix="%" />
                </b>
              </div>
              <div>
                <small>F1 Score</small>
                <b className="mono">
                  <ScrollCount value={bestModel.f1 * 100} decimals={2} suffix="%" />
                </b>
              </div>
            </div>

            <p className="lp-model-live-note">
              The live sensor runs a separate {liveModel.n_features}-feature model.
            </p>

            <div className="lp-model-bar-wrap">
              <div className="lp-model-bar-head mono">
                <span>F1 {(bestModel.f1 * 100).toFixed(2)} / 100</span>
              </div>
              <div
                className="lp-model-bar"
                role="progressbar"
                aria-label="F1 score"
                aria-valuenow={Number((bestModel.f1 * 100).toFixed(2))}
                aria-valuemin={0}
                aria-valuemax={100}
              >
                <div style={{ width: `${(bestModel.f1 * 100).toFixed(1)}%` }} />
              </div>
            </div>

            <p className="lp-model-signin">
              <Link to="/login">Sign in for the full comparison</Link>
            </p>
          </div>
        </div>
      </section>

      {/* 8. Footer */}
      <footer className="lp-foot">
        <div className="lp-foot-inner">
          <div className="lp-foot-brand">
            <div className="lp-logo"><span>Sentinel<em>IQ</em></span></div>
            <p>AI-based Real-Time Network Intrusion Detection System · Strictly Defensive Monitoring.</p>
            <p className="lp-foot-course">Course project · System Development · KUET</p>
          </div>
        </div>
        <div className="lp-foot-bottom mono">
          <span>© 2026 SentinelIQ · Defensive Security Project · KUET</span>
          <a
            href="#top"
            onClick={(e) => {
              e.preventDefault();
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
          >
            ↑ Back to top
          </a>
        </div>
      </footer>
    </div>
  );
}
