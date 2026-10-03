import { useState, useEffect } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './AuthContext';
import { ThemeToggle } from './ui';
import { useCriticalNotifier } from './notify';

const Icon = ({ d }) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
);

const links = [
  { to: '/', label: 'Dashboard', icon: 'M3 12l9-9 9 9M5 10v10h14V10' },
  { to: '/alerts', label: 'Alerts', icon: 'M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 01-3.4 0' },
  { to: '/analytics', label: 'Analytics', icon: 'M4 20V10M10 20V4M16 20v-8M22 20H2' },
  { to: '/assistant', label: 'AI Assistant', icon: 'M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z' },
  { to: '/settings', label: 'Settings', icon: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6' },
];

export default function Layout() {
  useCriticalNotifier();

  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();
  const close = () => setOpen(false);

  const current = links.find((l) => l.to === pathname);
  const title = current ? current.label : 'NIDS.AI';

  useEffect(() => { document.title = `${title} · NIDS.AI`; }, [title]);

  return (
    <div className="layout">
      {open && <div className="overlay" onClick={close} />}
      <aside className={'sidebar' + (open ? ' open' : '')}>
        <div className="brand">NIDS.AI</div>
        {links.map((l) => (
          <NavLink key={l.to} to={l.to} end={l.to === '/'} onClick={close}
            className={({ isActive }) => 'nav-link' + (isActive ? ' active' : '')}>
            <Icon d={l.icon} />{l.label}
          </NavLink>
        ))}
        <div className="side-foot">
          <div className="avatar">{(user.username || '?')[0].toUpperCase()}</div>
          <div><b>{user.username}</b><small>{user.role}</small></div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="menu-btn" onClick={() => setOpen(true)} aria-label="Menu">☰</button>
          <span className="page-title">{title}</span>
          <span className="uname">{user.username}</span>
          <span className="badge">{user.role}</span>
          <ThemeToggle />
          <button className="btn" onClick={logout} style={{ padding: '8px 14px' }}>Log out</button>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}