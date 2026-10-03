import { useEffect, useRef, useState } from 'react';
import { useTheme } from './theme';

export function Skeleton({ w = '100%', h = 20, r = 10 }) {
  return <div className="skel" style={{ width: w, height: h, borderRadius: r }} />;
}

export function CountUp({ value }) {
  const [n, setN] = useState(0);
  const from = useRef(0);
  useEffect(() => {
    const start = performance.now();
    const a = from.current;
    const b = Number(value) || 0;
    let raf;
    const tick = (t) => {
      const p = Math.min(1, (t - start) / 700);
      setN(Math.round(a + (b - a) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
      else from.current = b;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  return <>{n}</>;
}

export function ErrorBox({ message }) {
  return (
    <div className="err-box">
      <span>⚠ {message}</span>
      <button className="btn ghost sm" onClick={() => window.location.reload()}>Retry</button>
    </div>
  );
}

export function Empty({ icon = '🛡️', title, note }) {
  return (
    <div className="empty">
      <div className="big">{icon}</div>
      <div style={{ color: 'var(--text)', fontWeight: 600, marginBottom: 4 }}>{title}</div>
      <div style={{ fontSize: 13 }}>{note}</div>
    </div>
  );
}

export function ThemeToggle() {
  const [t, setT] = useTheme();
  return (
    <button className="theme-btn" onClick={() => setT(t === 'dark' ? 'light' : 'dark')}
      aria-label="Toggle theme" title={t === 'dark' ? 'Switch to light' : 'Switch to dark'}>
      {t === 'dark' ? '☀️' : '🌙'}
    </button>
  );
}