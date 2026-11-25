import { useEffect, useState, useCallback } from 'react';
import { useAuth } from './AuthContext';
import { alertsApi } from './api';
import { parseTimeMs } from './format';

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
  Low: 'var(--low)',
};

export function plainName(type, alertOrSignature = null) {
  const sig =
    typeof alertOrSignature === 'string'
      ? alertOrSignature.trim()
      : alertOrSignature && alertOrSignature.signature
        ? String(alertOrSignature.signature).trim()
        : '';

  if (sig) {
    const sUp = sig.toUpperCase();
    if (sUp.includes('SCAN') && (sUp.includes('3306') || sUp.includes('MYSQL'))) {
      return 'Someone scanned your database (MySQL, port 3306)';
    }
    if (sUp.includes('SCAN') && sUp.includes('SSH')) {
      return 'Someone scanned your SSH login service';
    }
    if (sUp.includes('SCAN') && (sUp.includes('NMAP') || sUp.includes('OS DETECTION'))) {
      return 'Someone scanned your network to identify devices';
    }
    if (sUp.includes('SCAN')) {
      return 'Someone scanned your network';
    }
    if (alertOrSignature && String(alertOrSignature.source || '').toLowerCase() === 'suricata') {
      return sig;
    }
  }

  const raw = String(type || '').trim();
  const key = raw.toLowerCase();
  if (!raw) return 'Unusual network activity';
  if (key.startsWith('et ') || key.startsWith('suricata ') || key.startsWith('gpl ')) {
    const rUp = raw.toUpperCase();
    if (rUp.includes('SCAN') && (rUp.includes('3306') || rUp.includes('MYSQL'))) {
      return 'Someone scanned your database (MySQL, port 3306)';
    }
    if (rUp.includes('SCAN')) return 'Someone scanned your network';
    return raw;
  }
  if (key === 'portscan' || key.includes('port scan') || key.includes('portscan')) {
    return 'Someone scanned your network';
  }
  if (key === 'bruteforce' || key.includes('brute')) {
    return 'Repeated login or connection attempts';
  }
  if (key.includes('dos') || key.includes('syn flood') || key.includes('synflood')) {
    return 'Flood of connection requests';
  }
  if (key.includes('udp')) {
    return 'Flood of data packets (UDP)';
  }
  if (key.includes('icmp')) {
    return 'Flood of ping requests';
  }
  if (key.includes('ml-detected') || key === 'ml' || key.includes('ml detected')) {
    return 'Unusual traffic detected';
  }
  return raw;
}

export const SEV_RANK = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

export function parseAlertTimeMs(t) {
  return parseTimeMs(t);
}

const POLL_PREF_KEY = 'sentineliq_poll_ms';
const SOUND_PREF_KEY = 'sentineliq_alert_sound';

export function getPollIntervalMs() {
  try {
    if (typeof localStorage === 'undefined') return 5000;
    const raw = localStorage.getItem(POLL_PREF_KEY);
    if (raw === null) return 5000;
    const n = Number(raw);
    return [0, 5000, 15000, 30000].includes(n) ? n : 5000;
  } catch {
    return 5000;
  }
}

export function setPollIntervalMs(ms) {
  const safe = [0, 5000, 15000, 30000].includes(Number(ms)) ? Number(ms) : 5000;
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(POLL_PREF_KEY, String(safe));
    }
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new Event('sentineliq:prefs-changed'));
    }
  } catch {
    /* ignore storage errors */
  }
  return safe;
}

export function getAlertSoundEnabled() {
  try {
    return typeof localStorage !== 'undefined' && localStorage.getItem(SOUND_PREF_KEY) === '1';
  } catch {
    return false;
  }
}

export function setAlertSoundEnabled(enabled) {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(SOUND_PREF_KEY, enabled ? '1' : '0');
    }
  } catch {
    /* ignore storage errors */
  }
  return !!enabled;
}

export function usePolling(path, ms = null) {
  const { token, logout } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [tick, setTick] = useState(0);
  const [prefMs, setPrefMs] = useState(getPollIntervalMs);

  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    const onPref = () => setPrefMs(getPollIntervalMs());
    window.addEventListener('sentineliq:prefs-changed', onPref);
    return () => window.removeEventListener('sentineliq:prefs-changed', onPref);
  }, []);

  const effectiveMs = ms !== null ? ms : prefMs;

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
    const id = effectiveMs > 0 ? setInterval(load, effectiveMs) : null;
    const onVis = () => {
      if (!document.hidden) load();
    };
    document.addEventListener('visibilitychange', onVis);
    return () => {
      alive = false;
      if (id) clearInterval(id);
      document.removeEventListener('visibilitychange', onVis);
    };
  }, [path, token, effectiveMs, tick]);

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

export function suggestedSteps(type) {
  const key = String(type || '').toLowerCase();
  if (key.includes('portscan') || key.includes('port scan') || key.includes('scan')) {
    return [
      'Block or rate-limit the scanning IP if you do not recognize it.',
      'Close unused ports and services on the target device.',
      'Watch this source IP for follow-up login or exploit attempts.',
    ];
  }
  if (key.includes('brute')) {
    return [
      'Block the source IP immediately to stop password guessing.',
      'Check that strong passwords, SSH keys, or MFA are enabled on the target.',
      'Review recent login logs for any successful sign-ins from this IP.',
    ];
  }
  if (key.includes('dos') || key.includes('syn')) {
    return [
      'Block the offending source IP to protect service availability.',
      'Enable SYN cookies or connection rate-limiting on the target host.',
      'Verify whether the target service is still responding normally.',
    ];
  }
  if (key.includes('udp')) {
    return [
      'Confirm this is not expected streaming, gaming, or VoIP traffic.',
      'Block or rate-limit UDP packets from the source IP if unexpected.',
      'Close unused UDP ports on the target device.',
    ];
  }
  if (key.includes('icmp')) {
    return [
      'Rate-limit or block inbound ping (ICMP) from untrusted hosts.',
      'Block the source IP if the flood is slowing down your network.',
    ];
  }
  if (key.includes('ml')) {
    return [
      'Check whether you recognize the source device and destination port.',
      'Use Explain with AI for a deeper breakdown of the traffic pattern.',
      'Block the source IP if the activity repeats and looks unexpected.',
    ];
  }
  return [
    'Verify whether the source IP belongs to a trusted device on your network.',
    'Block the source IP if the connection was unexpected.',
    'Mark the alert as investigated once reviewed.',
  ];
}

export function sanitizeNextPath(raw) {
  if (!raw || typeof raw !== 'string') return '/';
  const s = raw.trim();
  if (!s.startsWith('/') || s.startsWith('//') || s.startsWith('/\\') || s.includes('://')) {
    return '/';
  }
  if (
    s.startsWith('/login') ||
    s.startsWith('/register') ||
    s.startsWith('/forgot-password') ||
    s.startsWith('/reset-password') ||
    s.startsWith('/home')
  ) {
    return '/';
  }
  return s;
}

export function consumeNextPath(search = '') {
  let qNext = '';
  try {
    const params = new URLSearchParams(search);
    qNext = params.get('next') || '';
  } catch { /* ignore */ }
  let saved = '';
  try {
    saved = sessionStorage.getItem('nids_next_path') || '';
    sessionStorage.removeItem('nids_next_path');
  } catch { /* ignore */ }
  return sanitizeNextPath(qNext || saved || '/');
}
