import { useEffect, useState } from 'react';
import { useAuth } from './AuthContext';
import { alertsApi } from './api';

export function severity(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('dos') || t.includes('syn')) return 'Critical';
  if (t.includes('brute') || t.includes('udp') || t.includes('icmp')) return 'High';
  return 'Medium';
}

export const sevColor = {
  Critical: 'var(--danger)',
  High: 'var(--warn)',
  Medium: 'var(--accent)',
};

export function usePolling(path, ms = 5000) {
  const { token, logout } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const d = await alertsApi(path, { token });
        if (alive) { setData(d); setError(''); }
      } catch (e) {
        if (e.status === 401) logout();
        else if (alive) setError(e.message);
      }
    }
    load();
    const id = setInterval(load, ms);
    return () => { alive = false; clearInterval(id); };
  }, [path, token, ms]);

  return { data, error };
}
