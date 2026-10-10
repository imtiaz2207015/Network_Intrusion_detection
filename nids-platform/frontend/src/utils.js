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

