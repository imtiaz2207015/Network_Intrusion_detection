import { Link } from 'react-router-dom';
import { ThemeToggle } from './ui';
import './auth.css';

const FEATURES = [
  'Real-time detection across your local network',
  'Plain-English explanations for every alert',
  'Blocks attackers with one click',
];

export default function AuthShell({ title, sub, children }) {
  return (
    <div className="sp">
      <aside className="sp-left">
        <Link to="/home" className="sp-logo">
          <span className="sp-logo-badge" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
              <circle cx="12" cy="12" r="2.5" fill="currentColor" />
            </svg>
          </span>
          <span>Sentinel<em>IQ</em></span>
        </Link>

        <div className="sp-mid">
          <div className="radar" aria-hidden="true">
            <span className="radar-center" />
            <i className="blip b1" />
            <i className="blip b2" />
            <i className="blip b3" />
            <i className="blip b4" />
          </div>
          <h1 className="sp-h1">Detect threats <em>before</em> they spread.</h1>
          <p className="sp-p">
            Defensive network monitoring built for clarity and fast response.
          </p>
        </div>

        <ul className="sp-feature-list">
          {FEATURES.map((line) => (
            <li key={line}>
              <span className="sp-feature-dot" aria-hidden="true">✓</span>
              <span>{line}</span>
            </li>
          ))}
        </ul>
      </aside>

      <main className="sp-right">
        <div className="sp-top-actions">
          <ThemeToggle />
          <Link to="/home" className="sp-back">&larr; Back to website</Link>
        </div>
        <div className="sp-form">
          <div className="sp-mlogo" aria-hidden="true"><span>Sentinel<em>IQ</em></span></div>
          <h2>{title}</h2>
          <p className="au-sub">{sub}</p>
          {children}
        </div>
      </main>
    </div>
  );
}
