import { useState, useEffect } from 'react';

const KEY = 'nids-theme';
const LEGACY_KEY = 'theme';
const SIZE_KEY = 'nids-text-size';

export function getSystemTheme() {
  try {
    if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
  } catch {
    /* ignore */
  }
  return 'dark';
}

export function getTheme() {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === 'dark' || saved === 'light' || saved === 'system') {
      return saved;
    }
    const legacy = localStorage.getItem(LEGACY_KEY);
    if (legacy === 'dark' || legacy === 'light') {
      try {
        localStorage.setItem(KEY, legacy);
      } catch {
        /* ignore */
      }
      return legacy;
    }
  } catch {
    /* ignore */
  }
  return 'system';
}

export function resolveTheme(pref = getTheme()) {
  if (pref === 'dark' || pref === 'light') return pref;
  return getSystemTheme();
}

export function applyTheme(t) {
  const choice = t === 'dark' || t === 'light' || t === 'system' ? t : 'system';
  const effective = resolveTheme(choice);
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-theme', effective);
  }
  try {
    localStorage.setItem(KEY, choice);
  } catch {
    /* ignore */
  }
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new Event('themechange'));
  }
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

// Initialize theme, text size & pause CSS animations when tab is hidden
if (typeof document !== 'undefined') {
  document.documentElement.setAttribute('data-theme', resolveTheme(getTheme()));
  document.documentElement.setAttribute('data-text-size', getTextSize());
  const syncVis = () => {
    document.documentElement.setAttribute('data-tab-hidden', document.hidden ? 'true' : 'false');
  };
  document.addEventListener('visibilitychange', syncVis);
  syncVis();
}

export function useTheme() {
  const [t, setT] = useState(getTheme);
  const [resolved, setResolved] = useState(() => resolveTheme(getTheme()));

  useEffect(() => {
    const sync = () => {
      const currentPref = getTheme();
      const currentResolved = resolveTheme(currentPref);
      setT(currentPref);
      setResolved(currentResolved);
      if (typeof document !== 'undefined') {
        document.documentElement.setAttribute('data-theme', currentResolved);
      }
    };

    window.addEventListener('themechange', sync);

    let mq = null;
    const onSystemChange = () => {
      const currentPref = getTheme();
      const currentResolved = resolveTheme(currentPref);
      setResolved(currentResolved);
      if (currentPref === 'system' && typeof document !== 'undefined') {
        document.documentElement.setAttribute('data-theme', currentResolved);
      }
    };

    try {
      if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
        mq = window.matchMedia('(prefers-color-scheme: dark)');
        if (typeof mq.addEventListener === 'function') {
          mq.addEventListener('change', onSystemChange);
        } else if (typeof mq.addListener === 'function') {
          mq.addListener(onSystemChange);
        }
      }
    } catch {
      /* ignore */
    }

    return () => {
      window.removeEventListener('themechange', sync);
      try {
        if (mq) {
          if (typeof mq.removeEventListener === 'function') {
            mq.removeEventListener('change', onSystemChange);
          } else if (typeof mq.removeListener === 'function') {
            mq.removeListener(onSystemChange);
          }
        }
      } catch {
        /* ignore */
      }
    };
  }, []);

  return [t, applyTheme, resolved];
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
