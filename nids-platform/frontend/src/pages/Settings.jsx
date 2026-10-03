import { useState } from 'react';
import { useAuth } from '../AuthContext';
import { useTheme } from '../theme';
import { notifyEnabled, enableNotify, disableNotify, testNotify } from '../notify';

const row = { display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--border)', gap: 12 };

export default function Settings() {
  const { user, logout } = useAuth();
  const [theme, setTheme] = useTheme();
  const [on, setOn] = useState(notifyEnabled());
  const [msg, setMsg] = useState('');
  const initial = (user.username || '?')[0].toUpperCase();

  async function toggleNotify() {
    if (on) { disableNotify(); setOn(false); setMsg(''); return; }
    const r = await enableNotify();
    if (r === 'granted') { setOn(true); setMsg(''); }
    else if (r === 'unsupported') setMsg('Desktop notifications are not supported here (they need localhost or https).');
    else setMsg('Permission blocked. Allow notifications for this site in the address bar, then try again.');
  }

  return (
    <div style={{ display: 'grid', gap: 16, maxWidth: 720 }}>
      <h2>Settings</h2>

      <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
        <div style={{
          width: 64, height: 64, borderRadius: '50%', display: 'grid', placeItems: 'center',
          fontSize: 28, fontWeight: 700, color: '#050816', flexShrink: 0,
          background: 'linear-gradient(135deg, var(--accent), var(--accent-2))',
          boxShadow: '0 0 24px rgba(34,211,238,.35)',
        }}>{initial}</div>
        <div>
          <div style={{ fontSize: 20, fontWeight: 600 }}>{user.username}</div>
          <span className="badge" style={{ marginTop: 6 }}>{user.role}</span>
        </div>
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 12 }}>Appearance</div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button className={'btn sm' + (theme === 'dark' ? '' : ' ghost')} onClick={() => setTheme('dark')}>🌙 Dark</button>
          <button className={'btn sm' + (theme === 'light' ? '' : ' ghost')} onClick={() => setTheme('light')}>☀️ Light</button>
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontWeight: 600 }}>Desktop alerts</div>
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>Popup and beep when a new Critical alert arrives.</div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            {on && <button className="btn ghost sm" onClick={testNotify}>Send test</button>}
            <button className={'btn sm' + (on ? ' ghost' : '')} onClick={toggleNotify}>{on ? 'Turn off' : 'Enable'}</button>
          </div>
        </div>
        {msg && <p style={{ color: 'var(--danger)', fontSize: 13, marginTop: 12 }}>{msg}</p>}
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 6 }}>Account</div>
        <div style={row}><span style={{ color: 'var(--muted)' }}>Username</span><span>{user.username}</span></div>
        {user.email && (
          <div style={row}><span style={{ color: 'var(--muted)' }}>Email</span><span>{user.email}</span></div>
        )}
        <div style={{ ...row, borderBottom: 0 }}>
          <span style={{ color: 'var(--muted)' }}>Role</span><span>{user.role}</span>
        </div>
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 6 }}>About</div>
        <div style={row}><span style={{ color: 'var(--muted)' }}>System</span><span>NIDS.AI</span></div>
        <div style={row}><span style={{ color: 'var(--muted)' }}>Mode</span><span>Defensive (detection only)</span></div>
        <div style={{ ...row, borderBottom: 0 }}>
          <span style={{ color: 'var(--muted)' }}>Version</span><span>1.0</span>
        </div>
      </div>

      <div className="card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ fontWeight: 600 }}>Sign out</div>
          <div style={{ color: 'var(--muted)', fontSize: 13 }}>End your session on this device.</div>
        </div>
        <button className="btn" onClick={logout}>Log out</button>
      </div>
    </div>
  );
}