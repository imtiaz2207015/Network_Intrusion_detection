import { useState, useEffect } from 'react';

const KEY = 'nids-theme';

export function getTheme() {
  try { return localStorage.getItem(KEY) || 'dark'; } catch { return 'dark'; }
}

export function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
  window.dispatchEvent(new Event('themechange'));
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