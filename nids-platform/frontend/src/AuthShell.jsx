import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import './auth.css';

const SAMPLE = [
  ['Critical', 'DoS / SYN Flood', '10.0.0.23 → 10.0.0.5'],
  ['High', 'Brute Force on :22', '10.0.0.41 → 10.0.0.5'],
  ['Medium', 'Port Scan (ports 1-100)', '10.0.0.17 → 10.0.0.5'],
  ['High', 'UDP Flood', '10.0.0.88 → 10.0.0.5'],
  ['Low', 'ICMP Flood', '10.0.0.62 → 10.0.0.5'],
  ['Medium', 'ML: anomalous flow', '10.0.0.30 → 10.0.0.9'],
];

export default function AuthShell({ title, sub, children }) {
  const [n, setN] = useState(4);
  useEffect(() => {
    const t = setInterval(() => setN((x) => x + 1), 2400);
    return () => clearInterval(t);
  }, []);
  const rows = [0, 1, 2, 3].map((i) => ({ n: n - i, d: SAMPLE[(n - i) % SAMPLE.length] }));

  return (
    <div className="sp">
      <aside className="sp-left">
        <Link to="/home" className="sp-logo">NIDS<span>.</span>AI</Link>

        <div className="sp-mid">
          <div className="radar">
            <i className="blip b1" />
            <i className="blip b2" />
            <i className="blip b3" />
            <i className="blip b4" />
          </div>
          <h1 className="sp-h1">Detect threats <em>before</em> they spread.</h1>
          <p className="sp-p">Real-time network intrusion detection powered by machine learning and rule-based analysis.</p>
          <div className="sp-chips">
            <span>5 attack types</span>
            <span>ML + rules</span>
            <span>Live dashboard</span>
          </div>
        </div>

        <div className="sp-feed">
          <div className="sp-feed-head"><b /> Detection preview</div>
          {rows.map((r) => (
            <div className="sp-item" key={r.n}>
              <em className={'sev ' + r.d[0].toLowerCase()}>{r.d[0]}</em>
              <div>
                <strong>{r.d[1]}</strong>
                <small>{r.d[2]}</small>
              </div>
            </div>
          ))}
        </div>
      </aside>

      <main className="sp-right">
        <div className="sp-form">
          <Link to="/home" className="sp-mlogo">NIDS<span>.</span>AI</Link>
          <h2>{title}</h2>
          <p className="au-sub">{sub}</p>
          {children}
        </div>
      </main>
    </div>
  );
}