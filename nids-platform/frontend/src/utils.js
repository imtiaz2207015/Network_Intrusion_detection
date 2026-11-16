import { useEffect, useState, useCallback } from 'react';
import { useAuth } from './AuthContext';
import { alertsApi } from './api';

export function severity(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('dos') || t.includes('syn')) return 'Critical';
  if (t.includes('brute') || t.includes('udp') || t.includes('icmp')) return 'High';
  if (t.includes('low') || t.includes('info') || t.includes('benign')) return 'Low';
  return 'Medium';
}

export const sevColor = {
  Critical: 'var(--danger)',
  High: 'var(--high)',
  Medium: 'var(--warn)',
  Low: 'var(--muted)',
};

export const SEV_RANK = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

export function parseAlertTimeMs(t) {
  if (!t) return NaN;
  const s = String(t).trim().replace(' ', 'T');
  const ms = Date.parse(s.endsWith('Z') ? s : s + 'Z');
  return isNaN(ms) ? Date.parse(s) : ms;
}

export function usePolling(path, ms = 5000) {
  const { token, logout } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [tick, setTick] = useState(0);

  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let alive = true;
    async function load() {
      if (typeof document !== 'undefined' && document.hidden) return;
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
    const onVis = () => {
      if (!document.hidden) load();
    };
    document.addEventListener('visibilitychange', onVis);
    return () => {
      alive = false;
      clearInterval(id);
      document.removeEventListener('visibilitychange', onVis);
    };
  }, [path, token, ms, tick]);

  return { data, error, reload };
}

export const advice = {
  PortScan: {
    what: 'A host probed many ports in a short time to find open services.',
    risk: 'Usually the first step before a real attack.',
    actions: ['Block or rate-limit the source IP on the firewall.',
              'Close ports and services you do not need.',
              'Watch the same source for follow-up brute force or exploit attempts.'],
  },
  BruteForce: {
    what: 'Many rapid connection attempts to a login service (SSH, RDP, FTP, web).',
    risk: 'The attacker may be guessing passwords.',
    actions: ['Block the source IP temporarily.',
              'Enable account lockout and strong passwords or key-based login.',
              'Move the service off its default port or restrict it by IP / VPN.'],
  },
  'DoS/SYN Flood': {
    what: 'A flood of TCP connection requests meant to exhaust the target.',
    risk: 'The service can become slow or unreachable.',
    actions: ['Enable SYN cookies on the target server.',
              'Rate-limit new connections per source at the firewall.',
              'Block the source, or ask the ISP for upstream filtering.'],
  },
  'UDP Flood': {
    what: 'A high volume of UDP packets aimed at a host or port.',
    risk: 'Bandwidth and CPU exhaustion; may hide other attacks.',
    actions: ['Rate-limit UDP from the source.',
              'Block unused UDP ports.',
              'Check whether it is normal streaming traffic (video, VoIP) before blocking.'],
  },
  'ICMP Flood': {
    what: 'A large number of ping packets sent to a host.',
    risk: 'Network congestion or denial of service.',
    actions: ['Rate-limit ICMP echo requests.',
              'Block inbound ICMP from untrusted networks.',
              'Block the source IP.'],
  },
  'ML-Detected': {
    what: 'The machine-learning model flagged this flow as malicious based on its traffic features.',
    risk: 'Could be a real attack or an unusual-but-harmless flow.',
    actions: ['Check the source IP and destination port for context.',
              'Compare with rule-based alerts from the same source.',
              'If repeated, block the source and mark the alert as investigating.'],
  },
};

export function getAdvice(type) {
  const key = Object.keys(advice).find((k) => (type || '').toLowerCase().startsWith(k.toLowerCase()));
  return key ? advice[key] : {
    what: 'Suspicious network activity was detected.',
    risk: 'Unknown, so investigate.',
    actions: ['Check the source IP and destination.', 'Block the source if it is unexpected.'],
  };
}
