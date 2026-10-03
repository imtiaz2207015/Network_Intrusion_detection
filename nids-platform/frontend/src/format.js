export function timeAgo(t) {
  const ms = Date.parse(String(t).replace(' ', 'T') + 'Z');
  if (isNaN(ms)) return t;
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
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