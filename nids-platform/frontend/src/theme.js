import { useState, useEffect } from 'react';

const KEY = 'nids-theme';
const SIZE_KEY = 'nids-text-size';

export function getTheme() {
  try { return localStorage.getItem(KEY) || 'dark'; } catch { return 'dark'; }
}

export function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
  window.dispatchEvent(new Event('themechange'));
}

export function getTextSize() {
  try { return localStorage.getItem(SIZE_KEY) === 'large' ? 'large' : 'normal'; } catch { return 'normal'; }
}

export function applyTextSize(s) {
  const val = s === 'large' ? 'large' : 'normal';
  document.documentElement.setAttribute('data-text-size', val);
  try { localStorage.setItem(SIZE_KEY, val); } catch { /* ignore */ }
  window.dispatchEvent(new Event('textsizechange'));
}

// Initialize text size & pause CSS animations when tab is hidden
if (typeof document !== 'undefined') {
  document.documentElement.setAttribute('data-text-size', getTextSize());
  const syncVis = () => {
    document.documentElement.setAttribute('data-tab-hidden', document.hidden ? 'true' : 'false');
  };
  document.addEventListener('visibilitychange', syncVis);
  syncVis();
}

export function useTheme() {
  const [t, setT] = useState(getTheme);
  useEffect(() => {
    const h = () => setT(getTheme());
    window.addEventListener('themechange', h);
    return () => window.removeEventListener('themechange', h);
  }, []);
  return [t, applyTheme];
}

export function useTextSize() {
  const [s, setS] = useState(getTextSize);
  useEffect(() => {
    const h = () => setS(getTextSize());
    window.addEventListener('textsizechange', h);
    return () => window.removeEventListener('textsizechange', h);
  }, []);
  return [s, applyTextSize];
}
