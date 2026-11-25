import { useState, useEffect, useRef, useCallback, createElement } from 'react';
import { Link } from 'react-router-dom';
import { usePolling, severity, plainName, getAlertSoundEnabled } from './utils';
import { timeAgo } from './format';

function playAlertChime() {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(660, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.12);
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.26);
  } catch {
    /* ignore audio restrictions */
  }
}

const KEY = 'nids-notify';
const SOUND_KEY = 'nids-sound';
const LEVEL_KEY = 'nids-notify-level';
const POPUP_LEVEL_KEY = 'nids-popup-level';

export const POPUP_LEVELS = ['critical', 'critical_high', 'off'];

export const notifySupported = () => typeof window !== 'undefined' && 'Notification' in window;

export function getPopupLevel() {
  try {
    const raw = localStorage.getItem(POPUP_LEVEL_KEY);
    if (raw === 'critical' || raw === 'critical_high' || raw === 'off') {
      return raw;
    }
    const legacyOn = localStorage.getItem(KEY);
    const legacyLv = localStorage.getItem(LEVEL_KEY);
    if (legacyOn === 'off') return 'off';
    if (legacyLv === 'critical') return 'critical';
    if (legacyLv === 'high') return 'critical_high';
  } catch {
    /* ignore */
  }
  return 'critical_high';
}

export function setPopupLevel(level) {
  const next = POPUP_LEVELS.includes(level) ? level : 'critical_high';
  try {
    localStorage.setItem(POPUP_LEVEL_KEY, next);
    localStorage.setItem(KEY, next === 'off' ? 'off' : 'on');
    localStorage.setItem(LEVEL_KEY, next === 'critical' ? 'critical' : 'high');
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new Event('popuplevelchange'));
    }
  } catch {
    /* ignore */
  }
  return next;
}

export function notifyEnabled() {
  return getPopupLevel() !== 'off';
}

export function soundEnabled() {
  try {
    return localStorage.getItem(SOUND_KEY) !== 'off';
  } catch {
    return true;
  }
}

export function setSoundEnabled(on) {
  try {
    localStorage.setItem(SOUND_KEY, on ? 'on' : 'off');
  } catch {
    /* ignore */
  }
}

export function getNotifyLevel() {
  const lv = getPopupLevel();
  return lv === 'critical' ? 'critical' : 'high';
}

export function setNotifyLevel(level) {
  if (level === 'off') {
    setPopupLevel('off');
  } else if (level === 'critical') {
    setPopupLevel('critical');
  } else {
    setPopupLevel('critical_high');
  }
}

export async function enableNotify() {
  setPopupLevel('critical_high');
  return 'granted';
}

export function disableNotify() {
  setPopupLevel('off');
}

export function testNotify() {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('nids-test-popup'));
  }
}

export function matchesPopupLevel(sev, level) {
  if (level === 'off') return false;
  if (level === 'critical') return sev === 'Critical';
  return sev === 'Critical' || sev === 'High';
}

export function formatAlertPopupMeta(alert, nowTick) {
  void nowTick;
  const src = alert?.src || 'Unknown IP';
  const dport = alert?.dport && alert.dport !== '-' ? `port ${alert.dport}` : (alert?.dst && alert.dst !== '-' ? alert.dst : 'local network');
  const rel = alert?.time ? timeAgo(alert.time) : 'just now';
  return `${src} to ${dport}, ${rel}`;
}

export function AlertPopupCard({
  alert,
  preview = false,
  onDismiss,
  onMouseEnter,
  onMouseLeave,
}) {
  const sev = severity(alert?.type || 'DoS/SYN Flood');
  const sevClass =
    sev === 'Critical' ? 'critical' : sev === 'High' ? 'high' : 'neutral';
  const metaText = preview
    ? `${alert?.src || '203.0.113.42'} to port ${alert?.dport || '22'}, ${alert?.relTime || 'just now'}`
    : formatAlertPopupMeta(alert);

  const shieldIcon = createElement(
    'svg',
    {
      width: '17',
      height: '17',
      viewBox: '0 0 24 24',
      fill: 'none',
      stroke: 'currentColor',
      strokeWidth: '1.9',
      strokeLinecap: 'round',
      strokeLinejoin: 'round',
    },
    createElement('path', { d: 'M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z' }),
    createElement('line', { x1: '12', y1: '8.5', x2: '12', y2: '12.5' }),
    createElement('line', { x1: '12', y1: '16', x2: '12.01', y2: '16' })
  );

  const viewLink = preview
    ? createElement(
        Link,
        { to: '/alerts', className: 'alert-toast-btn primary' },
        'View details'
      )
    : createElement(
        Link,
        {
          to: alert?.id ? `/alerts?alert=${alert.id}` : '/alerts',
          className: 'alert-toast-btn primary',
          onClick: () => onDismiss && onDismiss(alert.id),
        },
        'View details'
      );

  const dismissBtn = createElement(
    'button',
    {
      type: 'button',
      className: 'alert-toast-btn',
      onClick: () => onDismiss && onDismiss(alert?.id),
      disabled: preview && !onDismiss,
    },
    'Dismiss'
  );

  return createElement(
    'div',
    {
      className: 'alert-toast-card' + (preview ? ' is-preview' : ''),
      role: preview ? 'region' : 'alert',
      'aria-label': preview ? 'Pop-up alert preview' : `${sev} alert: ${alert?.type || 'Security alert'}`,
      onMouseEnter,
      onMouseLeave,
    },
    createElement(
      'div',
      { className: 'alert-toast-top' },
      createElement(
        'div',
        { className: 'alert-toast-title-wrap' },
        createElement(
          'span',
          { className: 'alert-toast-icon ' + sevClass, 'aria-hidden': 'true' },
          shieldIcon
        ),
        createElement(
          'span',
          { className: 'alert-toast-heading' },
          plainName(alert?.type || 'BruteForce', alert)
        )
      ),
      createElement('span', { className: 'alert-toast-sev ' + sevClass }, sev)
    ),
    createElement('p', { className: 'alert-toast-meta' }, metaText),
    createElement('div', { className: 'alert-toast-actions' }, viewLink, dismissBtn)
  );
}

export function AlertToastStack({ toasts, onDismiss, onHoverChange }) {
  if (!Array.isArray(toasts) || toasts.length === 0) return null;
  return createElement(
    'div',
    {
      className: 'alert-toast-stack',
      'aria-live': 'polite',
      'aria-atomic': 'false',
      onMouseEnter: () => onHoverChange && onHoverChange(true),
      onMouseLeave: () => onHoverChange && onHoverChange(false),
    },
    toasts.map((t) =>
      createElement(AlertPopupCard, {
        key: t.id,
        alert: t,
        onDismiss,
      })
    )
  );
}

export function useCriticalNotifier() {
  const { data } = usePolling('/?limit=50');
  const seenIdsRef = useRef(null);
  const shownIdsRef = useRef(new Set());
  const [popupLevel, setPopupLevelState] = useState(getPopupLevel);
  const [toasts, setToasts] = useState([]);
  const [hovered, setHovered] = useState(false);

  // Keep popupLevel synced across Settings changes
  useEffect(() => {
    const sync = () => {
      const lv = getPopupLevel();
      setPopupLevelState(lv);
      if (lv === 'off') {
        setToasts([]);
      } else {
        setToasts((prev) => prev.filter((t) => matchesPopupLevel(severity(t.type), lv)));
      }
    };
    window.addEventListener('popuplevelchange', sync);
    window.addEventListener('storage', sync);
    return () => {
      window.removeEventListener('popuplevelchange', sync);
      window.removeEventListener('storage', sync);
    };
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Watch polled alerts and enqueue matching new alerts (newest on top, max 3, never twice for same alert.id)
  useEffect(() => {
    if (!data || !Array.isArray(data.alerts)) return;
    if (seenIdsRef.current === null) {
      seenIdsRef.current = new Set(data.alerts.map((a) => a.id));
      data.alerts.forEach((a) => shownIdsRef.current.add(a.id));
      return;
    }

    const fresh = data.alerts.filter((a) => !seenIdsRef.current.has(a.id));
    if (!fresh.length) return;
    fresh.forEach((a) => seenIdsRef.current.add(a.id));

    const lv = getPopupLevel();
    if (lv === 'off') return;

    const matched = fresh.filter((a) => {
      if (!a || a.id === undefined || a.id === null) return false;
      if (shownIdsRef.current.has(a.id)) return false;
      return matchesPopupLevel(severity(a.type), lv);
    });
    if (!matched.length) return;

    const now = Date.now();
    matched.forEach((a) => shownIdsRef.current.add(a.id));
    if (getAlertSoundEnabled()) {
      playAlertChime();
    }

    setToasts((prev) => {
      const incoming = matched
        .sort((a, b) => (Number(b.id) || 0) - (Number(a.id) || 0))
        .map((a) => ({
          ...a,
          _remainingMs: 8000,
          _lastTickMs: now,
        }));
      const existingIds = new Set(incoming.map((x) => x.id));
      const merged = [
        ...incoming,
        ...prev.filter((x) => !existingIds.has(x.id)),
      ];
      return merged.slice(0, 3);
    });
  }, [data]);

  // 8-second auto-dismiss timer that pauses while hovered
  useEffect(() => {
    if (toasts.length === 0 || hovered) return;
    const interval = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      setToasts((prev) =>
        prev
          .map((t) => ({
            ...t,
            _remainingMs: (t._remainingMs ?? 8000) - 250,
          }))
          .filter((t) => t._remainingMs > 0)
      );
    }, 250);
    return () => clearInterval(interval);
  }, [toasts.length, hovered]);

  return {
    data,
    toasts,
    dismissToast,
    setToastHovered: setHovered,
    popupLevel,
  };
}
