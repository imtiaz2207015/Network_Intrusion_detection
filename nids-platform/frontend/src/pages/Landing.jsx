import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import '../landing.css';
import { ThemeToggle } from '../ui';

const features = [
  ['Port Scan Detection', 'Flags hosts probing 10+ ports within seconds.'],
  ['Brute-Force Detection', 'Catches repeated login attempts on SSH, FTP, RDP and more.'],
  ['DoS / SYN Flood', 'Spots 100+ SYN packets per source in 5 seconds.'],
  ['UDP & ICMP Flood', 'Detects volumetric floods at the packet-rate level.'],
  ['ML Classification', 'Random Forest trained on CICIDS2017, 99%+ accuracy.'],
  ['Live Dashboard', 'Real-time alerts, severity levels and analytics.'],
];
const steps = [
  ['Capture', 'Sensor sniffs live packets with Scapy.'],
  ['Analyse', 'Flows are tracked and features extracted.'],
  ['Detect', 'Rules and ML model score each flow.'],
  ['Alert', 'Alerts reach your dashboard instantly.'],
];

export default function Landing() {
  const { token } = useAuth();
  const [menu, setMenu] = useState(false);

  useEffect(() => {
    document.title = 'NIDS.AI · Real-time intrusion detection';
    const els = document.querySelectorAll('.reveal');
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => {
        if (e.isIntersecting) { e.target.classList.add('show'); io.unobserve(e.target); }
      }),
      { threshold: 0.15 }
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  return (
    <div className="lp">
      <nav className="lp-nav">
        <div className="lp-logo">NIDS<span>.</span>AI</div>
        <div className={'lp-links' + (menu ? ' open' : '')} onClick={() => setMenu(false)}>
          <a href="#features">Features</a>
          <a href="#how">How it works</a>
          <a href="#contact">Contact</a>
        </div>
        <div className="lp-right">
          <ThemeToggle />
          <Link to={token ? '/' : '/login'} className="lp-signin">{token ? 'Dashboard' : 'Sign in'}</Link>
          <button className="lp-burger" onClick={() => setMenu(!menu)} aria-label="Menu">
            {menu ? '✕' : '☰'}
          </button>
        </div>
      </nav>

      <header className="lp-hero">
        <div>
          <h1>Protect Your <em>Network</em> in Real Time</h1>
          <p>AI-powered intrusion detection that watches your traffic, spots attacks as they happen, and explains them clearly.</p>
          <div className="lp-btns">
            <Link to={token ? '/' : '/register'} className="lp-btn primary">{token ? 'Open Dashboard' : 'Get Started'}</Link>
            <Link to={token ? '/alerts' : '/login'} className="lp-btn ghost">{token ? 'View Alerts' : 'Live Dashboard'}</Link>
          </div>
        </div>
        <svg className="lp-shield" viewBox="0 0 200 240" fill="none">
          <defs>
            <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor="#22d3ee" /><stop offset="1" stopColor="#8b5cf6" />
            </linearGradient>
          </defs>
          <path d="M100 10 L180 45 V120 C180 175 145 210 100 230 C55 210 20 175 20 120 V45 Z"
            fill="rgba(139,92,246,.15)" stroke="url(#g)" strokeWidth="4" />
          <rect x="68" y="105" width="64" height="52" rx="8" fill="url(#g)" />
          <path d="M80 105 V90 a20 20 0 0 1 40 0 V105" stroke="url(#g)" strokeWidth="8" fill="none" />
          <circle cx="100" cy="130" r="7" fill="#070b1a" />
        </svg>
      </header>

      <div className="lp-stats reveal">
        <div className="lp-stat"><b>5</b><span>Attack types detected</span></div>
        <div className="lp-stat"><b>99.9%</b><span>Model accuracy</span></div>
        <div className="lp-stat"><b>&lt;5s</b><span>Detection time</span></div>
        <div className="lp-stat"><b>24/7</b><span>Live monitoring</span></div>
      </div>

      <section className="lp-sec" id="features">
        <h2 className="reveal">What it detects</h2>
        <p className="sub reveal">Rule-based and ML detection working together</p>
        <div className="lp-grid">
          {features.map(([t, d], i) => (
            <div className="lp-card reveal" key={t} style={{ transitionDelay: `${i * 70}ms` }}>
              <h3>{t}</h3><p>{d}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="lp-sec" id="how">
        <h2 className="reveal">How it works</h2>
        <p className="sub reveal">From packet to alert in four steps</p>
        <div className="lp-grid">
          {steps.map(([t, d], i) => (
            <div className="lp-card lp-step reveal" key={t} style={{ transitionDelay: `${i * 90}ms` }}>
              <b>{i + 1}</b><h3>{t}</h3><p>{d}</p>
            </div>
          ))}
        </div>
      </section>

      <footer className="lp-foot" id="contact">
        © 2026 NIDS.AI · Defensive security project · KUET
        <div style={{ marginTop: 10 }}>
          <a href="#top" onClick={(e) => { e.preventDefault(); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>↑ Back to top</a>
        </div>
      </footer>
    </div>
  );
}