const MONTHS = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

export function parseTimeMs(t) {
  if (!t) return NaN;
  const raw = String(t).trim().replace(' ', 'T');
  const ms = Date.parse(raw.endsWith('Z') ? raw : raw + 'Z');
  return isNaN(ms) ? Date.parse(raw) : ms;
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
  const h24 = d.getHours();
  const m = d.getMinutes();
  const sec = d.getSeconds();
  const h12 = h24 % 12 === 0 ? 12 : h24 % 12;
  const ampm = h24 >= 12 ? 'PM' : 'AM';
  return `${month} ${day}, ${year}, ${String(h12).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')} ${ampm}`;
}

export function formatTimestamp(t) {
  if (!t) return '—';
  const d = new Date(String(t).trim().replace(' ', 'T'));
  const ms = parseTimeMs(t);
  if (isNaN(d) || isNaN(ms)) return String(t);

  const h24 = d.getHours();
  const m = d.getMinutes();
  const h12 = h24 % 12 === 0 ? 12 : h24 % 12;
  const ampm = h24 >= 12 ? 'PM' : 'AM';
  const clock = `${String(h12).padStart(2, '0')}:${String(m).padStart(2, '0')} ${ampm}`;

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
