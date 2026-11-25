import { useState, useEffect, useRef, useMemo } from 'react';
import { NavLink, Link, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './AuthContext';
import { ThemeToggle } from './ui';
import { useCriticalNotifier, AlertToastStack } from './notify';
import { severity, parseAlertTimeMs, usePolling } from './utils';
import { isCurrentlyBlocked } from './BlockedIps';
import SensorBadge from './SensorBadge';

const Icon = ({ d }) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
);

const navGroups = [
  {
    label: 'Monitor',
    items: [
      { to: '/', label: 'Dashboard', icon: 'M3 12l9-9 9 9M5 10v10h14V10' },
      { to: '/alerts', label: 'Alerts', icon: 'M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 01-3.4 0' },
      { to: '/blocked', label: 'Blocked IPs', icon: 'M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z' },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { to: '/analytics', label: 'Analytics', icon: 'M4 20V10M10 20V4M16 20v-8M22 20H2' },
      { to: '/models', label: 'Model Performance', icon: 'M12 2a10 10 0 100 20 10 10 0 000-20zM12 6a6 6 0 100 12 6 6 0 000-12zM12 10a2 2 0 100 4 2 2 0 000-4z' },
      { to: '/assistant', label: 'AI Assistant', icon: 'M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z' },
      { to: '/chat', label: 'AI Chat', icon: 'M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2zM9.5 11.5h5M12 9v5' },
    ],
  },
  {
    label: 'System',
    items: [
      { to: '/settings', label: 'Settings', icon: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6' },
      { to: '/help', label: 'Help', icon: 'M12 22a10 10 0 100-20 10 10 0 000 20zM9.09 9a3 3 0 015.83 1c0 2-3 3-3 3M12 17h.01' },
    ],
  },
];

const links = navGroups.flatMap((g) => g.items);

function updateFaviconBadge(count) {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 64;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Background shield circle
    ctx.fillStyle = '#0e1114';
    ctx.beginPath();
    ctx.arc(32, 32, 28, 0, Math.PI * 2);
    ctx.fill();
    ctx.lineWidth = 4;
    ctx.strokeStyle = count > 0 ? '#f87171' : '#2dd4bf';
    ctx.stroke();

    // Inner shield check mark
    ctx.strokeStyle = '#2dd4bf';
    ctx.lineWidth = 4;
    ctx.beginPath();
    ctx.moveTo(22, 33);
    ctx.lineTo(29, 40);
    ctx.lineTo(43, 25);
    ctx.stroke();

    if (count > 0) {
      const text = count > 99 ? '99+' : String(count);
      ctx.fillStyle = '#dc2626';
      ctx.beginPath();
      ctx.arc(48, 16, 15, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 17px sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(text, 48, 17);
    }

    let link = document.querySelector("link[rel~='icon']");
    if (!link) {
      link = document.createElement('link');
      link.rel = 'icon';
      document.head.appendChild(link);
    }
    link.href = canvas.toDataURL('image/png');
  } catch {
    /* ignore canvas restrictions */
  }
}

export default function Layout() {
  const {
    data: pollData,
    toasts,
    dismissToast,
    setToastHovered,
  } = useCriticalNotifier();
  const { data: blockedPoll } = usePolling('/blocked-ips', 5000);
  const activeBlockCount = useMemo(() => {
    const list = blockedPoll?.blocked;
    if (!Array.isArray(list)) return 0;
    return list.filter((r) => isCurrentlyBlocked(r.status)).length;
  }, [blockedPoll]);

  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem('sidebar') === 'closed'
  );
  const [welcome, setWelcome] = useState(() => {
    try {
      const key = `nids_welcomed_${user?.username || 'user'}`;
      if (sessionStorage.getItem(key)) return false;
      sessionStorage.setItem(key, '1');
      return true;
    } catch {
      return false;
    }
  });

  const [attackDismissed, setAttackDismissed] = useState(() => {
    try {
      return sessionStorage.getItem('nids_attack_dismissed') === '1';
    } catch {
      return false;
    }
  });

  const [nowMs, setNowMs] = useState(() => Date.now());
  const seenMaxIdRef = useRef(null);
  const [unseenCount, setUnseenCount] = useState(0);

  const { pathname } = useLocation();
  const close = () => setOpen(false);

  useEffect(() => {
    localStorage.setItem('sidebar', collapsed ? 'closed' : 'open');
  }, [collapsed]);

  useEffect(() => {
    if (!welcome) return;
    const t = setTimeout(() => setWelcome(false), 1250);
    return () => clearTimeout(t);
  }, [welcome]);

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e) => e.key === 'Escape' && setOpen(false);
    window.addEventListener('keydown', onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [open]);

  // Track unseen alerts since the user last visited /alerts
  useEffect(() => {
    const list = pollData?.alerts;
    if (!Array.isArray(list)) return;
    const maxId = list.reduce((m, a) => Math.max(m, Number(a.id) || 0), 0);

    if (seenMaxIdRef.current === null) {
      let saved = null;
      try {
        const raw = sessionStorage.getItem('nids_last_seen_alert_id');
        if (raw !== null) saved = Number(raw);
      } catch { /* ignore */ }
      seenMaxIdRef.current = saved !== null && !isNaN(saved) ? saved : maxId;
      try {
        sessionStorage.setItem('nids_last_seen_alert_id', String(seenMaxIdRef.current));
      } catch { /* ignore */ }
    }

    if (pathname === '/alerts') {
      seenMaxIdRef.current = Math.max(seenMaxIdRef.current, maxId);
      try {
        sessionStorage.setItem('nids_last_seen_alert_id', String(seenMaxIdRef.current));
      } catch { /* ignore */ }
      setUnseenCount(0);
    } else {
      const count = list.filter((a) => (Number(a.id) || 0) > seenMaxIdRef.current).length;
      setUnseenCount(count);
    }
  }, [pollData, pathname]);

  // Reset unseen count immediately when navigating to /alerts
  useEffect(() => {
    if (pathname === '/alerts') {
      const list = pollData?.alerts;
      if (Array.isArray(list) && list.length > 0) {
        const maxId = list.reduce((m, a) => Math.max(m, Number(a.id) || 0), 0);
        seenMaxIdRef.current = Math.max(seenMaxIdRef.current ?? 0, maxId);
        try {
          sessionStorage.setItem('nids_last_seen_alert_id', String(seenMaxIdRef.current));
        } catch { /* ignore */ }
      }
      setUnseenCount(0);
    }
  }, [pathname, pollData]);

  // Update document.title and favicon badge
  useEffect(() => {
    document.title = unseenCount > 0 ? `(${unseenCount}) SentinelIQ` : 'SentinelIQ';
    updateFaviconBadge(unseenCount);
  }, [unseenCount]);

  // Compute Critical alerts in the last 60 seconds for the "Under attack" banner
  const recentCritCount = useMemo(() => {
    const list = pollData?.alerts;
    if (!Array.isArray(list)) return 0;
    return list.filter((a) => {
      if (severity(a.type) !== 'Critical') return false;
      const ms = parseAlertTimeMs(a.time);
      return !isNaN(ms) && nowMs - ms >= -5000 && nowMs - ms <= 60000;
    }).length;
  }, [pollData, nowMs]);

  // Tick every second while critical alerts exist in the 60s window so it auto-hides after 60s
  useEffect(() => {
    setNowMs(Date.now());
  }, [pollData]);

  useEffect(() => {
    if (recentCritCount === 0) return;
    const id = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      setNowMs(Date.now());
    }, 1000);
    return () => clearInterval(id);
  }, [recentCritCount]);

  const underAttack = recentCritCount >= 3 && !attackDismissed;

  function dismissAttackBanner() {
    setAttackDismissed(true);
    try {
      sessionStorage.setItem('nids_attack_dismissed', '1');
    } catch { /* ignore */ }
  }

  const handleLogout = () => {
    try {
      sessionStorage.removeItem(`nids_welcomed_${user?.username || 'user'}`);
    } catch { /* ignore */ }
    logout();
  };

  const toggleSidebar = () => {
    if (window.matchMedia('(max-width: 900px)').matches) setOpen((o) => !o);
    else setCollapsed((c) => !c);
  };

  const current = links.find((l) => l.to === pathname);
  const title = current ? current.label : 'Overview';

  return (
    <div className={'layout' + (collapsed ? ' collapsed' : '') + (underAttack ? ' under-attack' : '')}>
      {welcome && (
        <div className="login-welcome-overlay" onClick={() => setWelcome(false)} role="status" aria-live="polite">
          <div className="login-welcome-scan" />
          <div className="login-welcome-card">
            <div className="login-welcome-radar">
              <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
                <polyline points="9 12 11 14 15 10" />
              </svg>
            </div>
            <div className="login-welcome-text">
              <span className="mono login-welcome-kicker">SESSION AUTHENTICATED · TELEMETRY LINK ACTIVE</span>
              <strong>Welcome back, {user.username}</strong>
              <small className="mono">Role: {user.role} · Syncing live sensor &amp; ML engine...</small>
            </div>
          </div>
        </div>
      )}

      {open && <div className="overlay" onClick={close} />}
      <aside className={'sidebar' + (open ? ' open' : '')} aria-label="Main navigation">
        <div className="sidebar-head">
          <div className="brand brand-wrap">
            <span className="brand-mark" aria-hidden="true">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
              </svg>
            </span>
            <span>Sentinel<em>IQ</em></span>
          </div>
          <button className="sidebar-close-btn" onClick={close} aria-label="Close navigation drawer">✕</button>
        </div>
        {navGroups.map((grp) => (
          <div key={grp.label} className="nav-group">
            <div className="nav-group-label">{grp.label}</div>
            {grp.items.map((l) => (
              <NavLink key={l.to} to={l.to} end={l.to === '/'} onClick={close}
                className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}>
                <Icon d={l.icon} />
                <span>{l.label}</span>
                {l.to === '/alerts' && unseenCount > 0 && (
                  <span className="nav-unseen-pill mono">{unseenCount}</span>
                )}
                {l.to === '/blocked' && activeBlockCount > 0 && (
                  <span className="nav-unseen-pill mono">{activeBlockCount}</span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
        <div className="drawer-sensor-status">
          <SensorBadge showFull />
        </div>
        <div className="side-foot">
          <div className="avatar">{(user.username || '?')[0].toUpperCase()}</div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <b style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {user.username}
            </b>
            <span className="side-role-pill mono">{user.role}</span>
          </div>
          <button
            type="button"
            className="side-logout-icon"
            onClick={handleLogout}
            aria-label="Log out"
            title="Log out"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
          </button>
        </div>
        <button type="button" className="btn ghost drawer-logout-btn" onClick={handleLogout}>
          Log out
        </button>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="menu-btn" onClick={toggleSidebar} aria-label="Toggle sidebar">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="2" strokeLinecap="round"><path d="M4 6h16M4 12h16M4 18h16" /></svg>
          </button>
          <nav className="topbar-crumb" aria-label="Breadcrumb">
            <Link to="/" className="crumb-home">Home</Link>
            <span className="crumb-sep" aria-hidden="true">/</span>
            <span className="crumb-current" aria-current="page">{title}</span>
          </nav>
          <SensorBadge />
          <ThemeToggle />
        </header>

        {underAttack && (
          <div className="under-attack-banner" role="alert">
            <div className="under-attack-left">
              <span className="under-attack-dot" aria-hidden="true" />
              <strong>
                Under attack: {recentCritCount} critical alerts in the last minute
              </strong>
            </div>
            <div className="under-attack-actions">
              <Link to="/alerts" className="btn sm under-attack-link">
                View alerts
              </Link>
              <button
                type="button"
                className="under-attack-dismiss"
                onClick={dismissAttackBanner}
                aria-label="Dismiss under attack banner"
              >
                ✕
              </button>
            </div>
          </div>
        )}

        <main className="content">
          <Outlet />
        </main>

        <AlertToastStack
          toasts={toasts}
          onDismiss={dismissToast}
          onHoverChange={setToastHovered}
        />
      </div>
    </div>
  );
}
