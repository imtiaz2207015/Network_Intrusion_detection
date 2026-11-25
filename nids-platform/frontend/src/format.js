const MONTHS = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

const TIME_24H_KEY = 'sentineliq_time_24h';

export function getTimeFormat24h() {
  try {
    return typeof localStorage !== 'undefined' && localStorage.getItem(TIME_24H_KEY) === '1';
  } catch {
    return false;
  }
}

export function setTimeFormat24h(use24h) {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(TIME_24H_KEY, use24h ? '1' : '0');
    }
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new Event('sentineliq:prefs-changed'));
    }
  } catch {
    /* ignore storage errors */
  }
}

function formatClock(h24, m, sec = null) {
  const mm = String(m).padStart(2, '0');
  const ss = sec === null ? '' : `:${String(sec).padStart(2, '0')}`;
  if (getTimeFormat24h()) {
    return `${String(h24).padStart(2, '0')}:${mm}${ss}`;
  }
  const h12 = h24 % 12 === 0 ? 12 : h24 % 12;
  const ampm = h24 >= 12 ? 'PM' : 'AM';
  return `${String(h12).padStart(2, '0')}:${mm}${ss} ${ampm}`;
}

export function parseTimeMs(t) {
  if (!t) return NaN;
  if (typeof t === 'number') return t < 1e12 ? t * 1000 : t;
  const raw = String(t).trim().replace(' ', 'T');
  // Respect explicit timezone (Z or +/-HH:MM); otherwise treat sensor timestamps as local time
  if (/(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw)) {
    const ms = Date.parse(raw);
    return isNaN(ms) ? NaN : ms;
  }
  const m = raw.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/);
  if (m) {
    return new Date(
      Number(m[1]),
      Number(m[2]) - 1,
      Number(m[3]),
      Number(m[4]),
      Number(m[5]),
      Number(m[6] || 0)
    ).getTime();
  }
  const ms = Date.parse(raw);
  return isNaN(ms) ? NaN : ms;
}

export function humanAge(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  if (s < 10) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return h > 0 ? `${d}d ${h}h ago` : `${d}d ago`;
}

export function shortAge(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  if (s < 10) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function timeAgo(t) {
  const ms = parseTimeMs(t);
  if (isNaN(ms)) return t;
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  return humanAge(s);
}

export function formatAbsoluteTime(t) {
  if (!t) return '—';
  const d = new Date(String(t).trim().replace(' ', 'T'));
  if (isNaN(d)) return String(t);
  const month = MONTHS[d.getMonth()];
  const day = d.getDate();
  const year = d.getFullYear();
  return `${month} ${day}, ${year}, ${formatClock(d.getHours(), d.getMinutes(), d.getSeconds())}`;
}

export function formatTimeParts(t) {
  if (!t) return { date: '—', age: '' };
  const d = new Date(String(t).trim().replace(' ', 'T'));
  const ms = parseTimeMs(t);
  if (isNaN(d) || isNaN(ms)) return { date: String(t), age: '' };
  const month = MONTHS[d.getMonth()];
  const day = d.getDate();
  const clock = formatClock(d.getHours(), d.getMinutes());
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  return {
    date: `${month} ${day}, ${clock}`,
    age: shortAge(s),
  };
}

export function formatTimestamp(t) {
  if (!t) return '—';
  const d = new Date(String(t).trim().replace(' ', 'T'));
  const ms = parseTimeMs(t);
  if (isNaN(d) || isNaN(ms)) return String(t);

  const clock = formatClock(d.getHours(), d.getMinutes());
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  const age = shortAge(s);

  if (s < 86400) {
    return `${clock} · ${age}`;
  }
  const month = MONTHS[d.getMonth()];
  const day = d.getDate();
  return `${month} ${day}, ${clock} · ${age}`;
}

export function downloadCSV(rows, name = 'alerts.csv') {
  const head = ['Time', 'Type', 'Source', 'Destination', 'Port', 'Details'];
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [
    head.join(','),
    ...rows.map((a) => [a.time, a.type, a.src, a.dst, a.dport, a.detail].map(esc).join(',')),
  ];
  const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' }));
  const el = document.createElement('a');
  el.href = url;
  el.download = name;
  el.click();
  URL.revokeObjectURL(url);
}
