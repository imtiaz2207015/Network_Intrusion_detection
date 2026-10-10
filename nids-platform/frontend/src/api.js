async function request(base, path, { method = 'GET', body, token } = {}) {
  const res = await fetch(base + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

export const api = (path, opts) => request('/api/auth', path, opts);
export const alertsApi = (path, opts) => request('/api/alerts', path, opts);

export async function downloadReport(token, hours = 24) {
  const res = await fetch(`/api/analytics/report.pdf?hours=${hours}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`Report failed (${res.status})`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'nids-report.pdf';
  a.click();
  URL.revokeObjectURL(url);
}
export const analyticsApi = (path, opts) => request('/api/analytics', path, opts);