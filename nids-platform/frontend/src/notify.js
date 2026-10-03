import { useEffect, useRef } from 'react';
import { usePolling, severity } from './utils';

const KEY = 'nids-notify';

export const notifySupported = () => 'Notification' in window;

export function notifyEnabled() {
  try {
    return localStorage.getItem(KEY) === 'on' && notifySupported() && Notification.permission === 'granted';
  } catch { return false; }
}

function beep() {
  try {
    const c = new (window.AudioContext || window.webkitAudioContext)();
    const o = c.createOscillator();
    const g = c.createGain();
    o.connect(g); g.connect(c.destination);
    o.frequency.value = 880;
    g.gain.setValueAtTime(0.15, c.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001, c.currentTime + 0.4);
    o.start(); o.stop(c.currentTime + 0.4);
  } catch { /* ignore */ }
}

function show(title, body, tag) {
  try {
    const n = new Notification(title, { body, tag });
    n.onclick = () => { window.focus(); n.close(); };
    beep();
  } catch { /* ignore */ }
}

export async function enableNotify() {
  try {
    if (!notifySupported()) return 'unsupported';
    const p = await Notification.requestPermission();
    if (p === 'granted') {
      try { localStorage.setItem(KEY, 'on'); } catch { /* ignore */ }
      show('NIDS.AI alerts enabled', 'You will be notified of new critical alerts.', 'nids-info');
    }
    return p;
  } catch { return 'unsupported'; }
}

export function disableNotify() {
  try { localStorage.setItem(KEY, 'off'); } catch { /* ignore */ }
}

export function testNotify() {
  if (notifyEnabled()) show('Critical: DoS (test)', 'This is a test alert from NIDS.AI.', 'nids-test');
}

export function useCriticalNotifier() {
  const { data } = usePolling('/?limit=50');
  const seen = useRef(null);

  useEffect(() => {
    if (!data || !data.alerts) return;
    if (seen.current === null) {
      seen.current = new Set(data.alerts.map((a) => a.id));
      return;
    }
    const fresh = data.alerts.filter((a) => !seen.current.has(a.id));
    fresh.forEach((a) => seen.current.add(a.id));
    if (!notifyEnabled()) return;
    const crit = fresh.filter((a) => severity(a.type) === 'Critical');
    if (!crit.length) return;
    const a = crit[0];
    if (crit.length > 1) {
      show(`${crit.length} new critical alerts`, `Latest: ${a.type} from ${a.src}`, 'nids-critical');
    } else {
      show(`Critical: ${a.type}`, `From ${a.src} to ${a.dst}${a.dport && a.dport !== '-' ? ':' + a.dport : ''}`, 'nids-critical');
    }
  }, [data]);
}