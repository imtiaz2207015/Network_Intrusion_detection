import { useEffect, useRef } from 'react';
import { usePolling, severity } from './utils';

const KEY = 'nids-notify';
const SOUND_KEY = 'nids-sound';
const LEVEL_KEY = 'nids-notify-level';

export const notifySupported = () => 'Notification' in window;

export function notifyEnabled() {
  try {
    return localStorage.getItem(KEY) === 'on' && notifySupported() && Notification.permission === 'granted';
  } catch { return false; }
}

export function soundEnabled() {
  try {
    return localStorage.getItem(SOUND_KEY) !== 'off';
  } catch { return true; }
}

export function setSoundEnabled(on) {
  try {
    localStorage.setItem(SOUND_KEY, on ? 'on' : 'off');
  } catch { /* ignore */ }
}

export function getNotifyLevel() {
  try {
    return localStorage.getItem(LEVEL_KEY) === 'high' ? 'high' : 'critical';
  } catch { return 'critical'; }
}

export function setNotifyLevel(level) {
  try {
    localStorage.setItem(LEVEL_KEY, level === 'high' ? 'high' : 'critical');
  } catch { /* ignore */ }
}

function beep() {
  if (!soundEnabled()) return;
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
      show('SentinelIQ alerts enabled', 'You will be notified when new threats are detected.', 'nids-info');
    }
    return p;
  } catch { return 'unsupported'; }
}

export function disableNotify() {
  try { localStorage.setItem(KEY, 'off'); } catch { /* ignore */ }
}

export function testNotify() {
  if (notifyEnabled()) show('Critical: DoS (test)', 'This is a test alert from SentinelIQ.', 'nids-test');
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

    const level = getNotifyLevel();
    const matched = fresh.filter((a) => {
      const s = severity(a.type);
      return level === 'high' ? (s === 'Critical' || s === 'High') : s === 'Critical';
    });
    if (!matched.length) return;
    const a = matched[0];
    const sev = severity(a.type);
    if (matched.length > 1) {
      show(`${matched.length} new security alerts`, `Latest: ${a.type} from ${a.src}`, 'nids-critical');
    } else {
      show(`${sev}: ${a.type}`, `From ${a.src} to ${a.dst}${a.dport && a.dport !== '-' ? ':' + a.dport : ''}`, 'nids-critical');
    }
  }, [data]);

  return { data };
}
