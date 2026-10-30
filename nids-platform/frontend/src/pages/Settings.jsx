import { useState } from 'react';
import { useAuth } from '../AuthContext';
import { useTheme } from '../theme';
import { notifyEnabled, enableNotify, disableNotify, testNotify } from '../notify';
import { api } from '../api';

const row = { display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid var(--border)', gap: 12 };

function ChangePassword({ token }) {
  const [cur, setCur] = useState('');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [ok, setOk] = useState('');

  async function submit(e) {
    e.preventDefault();
    setErr(''); setOk('');
    if (pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)) {
      setErr('New password: at least 8 characters with letters and numbers');
      return;
    }
    if (pw !== pw2) { setErr('New passwords do not match'); return; }
    setBusy(true);
    try {
      await api('/change-password', {
        method: 'POST', token,
        body: { current_password: cur, new_password: pw },
      });
      setOk('Password changed.');
      setCur(''); setPw(''); setPw2('');
    } catch (e2) {
      setErr(e2.message);
    }
    setBusy(false);
  }

  return (
    <div className="card">
      <div className="stat-label" style={{ marginBottom: 12 }}>Change password</div>
      <form onSubmit={submit} style={{ display: 'grid', gap: 10, maxWidth: 360 }}>
        <input className="input" type="password" placeholder="Current password"
          autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
        <input className="input" type="password" placeholder="New password"
          autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
        <input className="input" type="password" placeholder="Confirm new password"
          autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
        <button className="btn sm" type="submit" disabled={busy}>
          {busy ? 'Saving...' : 'Update password'}
        </button>
      </form>
      {err && <p style={{ color: 'var(--danger)', fontSize: 13, marginTop: 12 }}>{err}</p>}
      {ok && <p style={{ color: 'var(--accent)', fontSize: 13, marginTop: 12 }}>{ok}</p>}
    </div>
  );
}

export default function Settings() {
  const { user, token, logout } = useAuth();
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

      <ChangePassword token={token} />

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