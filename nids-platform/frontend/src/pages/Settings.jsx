import { useState } from 'react';
import { useAuth } from '../AuthContext';
import { useTheme, useTextSize } from '../theme';
import {
  notifyEnabled,
  enableNotify,
  disableNotify,
  testNotify,
  soundEnabled,
  setSoundEnabled,
  getNotifyLevel,
  setNotifyLevel,
} from '../notify';
import ChangePassword from './ChangePassword';

const row = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  padding: '11px 0',
  borderBottom: '1px solid var(--border)',
  gap: 12,
  fontSize: 13.5,
};

export default function Settings() {
  const { user, token } = useAuth();
  const [theme, setTheme] = useTheme();
  const [textSize, setTextSize] = useTextSize();
  const [on, setOn] = useState(notifyEnabled());
  const [sound, setSound] = useState(soundEnabled());
  const [level, setLevel] = useState(getNotifyLevel());
  const [msg, setMsg] = useState('');

  const initial = (user.username || '?')[0].toUpperCase();
  const memberSince = user.created_at || user.member_since || '';

  async function toggleNotify() {
    if (on) {
      disableNotify();
      setOn(false);
      setMsg('');
      return;
    }
    const r = await enableNotify();
    if (r === 'granted') {
      setOn(true);
      setMsg('');
    } else if (r === 'unsupported') {
      setMsg('Desktop notifications are not supported here (they need localhost or https).');
    } else {
      setMsg('Permission blocked. Allow notifications for this site in the address bar, then try again.');
    }
  }

  function toggleSound() {
    const next = !sound;
    setSound(next);
    setSoundEnabled(next);
  }

  function changeLevel(lv) {
    setLevel(lv);
    setNotifyLevel(lv);
  }

  return (
    <div className="st">
      <div style={{ marginBottom: 16 }}>
        <h2>Settings &amp; Preferences</h2>
        <p className="band-sub">
          Customize how SentinelIQ looks, how it alerts you, and check your protection status in plain English.
        </p>
      </div>

      <div className="st-cols">
        {/* 1. Merged Account & Profile Card */}
        <div className="card">
          <div className="st-profile-card" style={{ padding: 0, border: 0, background: 'transparent', marginBottom: 14 }}>
            <div className="st-avatar">{initial}</div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-head)' }}>
                  {user.username}
                </span>
                <span className="badge mono" style={{ color: 'var(--accent)', borderColor: 'var(--accent-border)' }}>
                  {user.role}
                </span>
              </div>
              <div style={{ color: 'var(--muted)', fontSize: 13, marginTop: 4 }}>
                {user.email || 'Signed in to SentinelIQ Network Protection'}
              </div>
            </div>
          </div>

          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 4 }}>
            <div style={row}>
              <span style={{ color: 'var(--muted)' }}>Username</span>
              <span className="mono">{user.username}</span>
            </div>
            {user.email && (
              <div style={row}>
                <span style={{ color: 'var(--muted)' }}>Email</span>
                <span className="mono">{user.email}</span>
              </div>
            )}
            <div style={row}>
              <span style={{ color: 'var(--muted)' }}>Account Role</span>
              <span className="mono" style={{ textTransform: 'capitalize', color: 'var(--accent)' }}>{user.role}</span>
            </div>
            {memberSince && (
              <div style={row}>
                <span style={{ color: 'var(--muted)' }}>Member Since</span>
                <span className="mono">{memberSince}</span>
              </div>
            )}
            <div style={row}>
              <span style={{ color: 'var(--muted)' }}>Protection Mode</span>
              <span>Defensive (Detection &amp; Guidance Only)</span>
            </div>
            <div style={{ ...row, borderBottom: 0 }}>
              <span style={{ color: 'var(--muted)' }}>System Documentation</span>
              <a href="/docs/index.html" target="_blank" rel="noopener noreferrer" className="mono" style={{ fontSize: 13 }}>
                Open API Docs (Swagger) ↗
              </a>
            </div>
          </div>
        </div>

        {/* 2. Appearance & Text Size */}
        <div className="card">
          <div className="stat-label" style={{ marginBottom: 6 }}>Appearance &amp; Reading Comfort</div>
          <p className="band-sub" style={{ marginBottom: 14 }}>
            Choose a dark or light color theme and adjust the text size for comfortable reading.
          </p>
          <div className="st-theme-grid">
            <button
              type="button"
              className={'st-theme-opt' + (theme === 'dark' ? ' active' : '')}
              onClick={() => setTheme('dark')}
            >
              <span className="st-theme-swatch dark" />
              <div>
                <b>🌙 Dark Mode</b>
                <small>Easy on the eyes in low light</small>
              </div>
            </button>
            <button
              type="button"
              className={'st-theme-opt' + (theme === 'light' ? ' active' : '')}
              onClick={() => setTheme('light')}
            >
              <span className="st-theme-swatch light" />
              <div>
                <b>☀️ Light Mode</b>
                <small>Bright daylight background</small>
              </div>
            </button>
          </div>

          <div className="st-sub-setting">
            <div>
              <div style={{ fontWeight: 600, fontSize: 14 }}>Text Size</div>
              <div style={{ color: 'var(--muted)', fontSize: 12.5 }}>Make words and numbers larger across all pages.</div>
            </div>
            <div className="an-range-pills">
              <button
                type="button"
                className={'an-pill' + (textSize === 'normal' ? ' active' : '')}
                onClick={() => setTextSize('normal')}
              >
                A Normal
              </button>
              <button
                type="button"
                className={'an-pill' + (textSize === 'large' ? ' active' : '')}
                onClick={() => setTextSize('large')}
              >
                A+ Large Text
              </button>
            </div>
          </div>
        </div>

        {/* 4. Desktop Alerts + Sound & Severity Controls */}
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontWeight: 600 }}>Desktop Pop-Up Alerts</span>
                <span className={'status-pill ' + (on ? 'resolved' : 'new')}>
                  <i /> {on ? 'Enabled' : 'Off'}
                </span>
              </div>
              <div style={{ color: 'var(--muted)', fontSize: 13, marginTop: 4 }}>
                Show a pop-up message on your computer even when you are looking at another tab.
              </div>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              {on && <button className="btn ghost sm" onClick={testNotify}>Send test</button>}
              <button className={'btn sm' + (on ? ' ghost' : '')} onClick={toggleNotify}>
                {on ? 'Turn off' : 'Enable'}
              </button>
            </div>
          </div>

          {msg && <p style={{ color: 'var(--danger)', fontSize: 13, marginTop: 12 }}>{msg}</p>}

          <div className="st-sub-setting">
            <div>
              <div style={{ fontWeight: 600, fontSize: 14 }}>Alert Sound (Beep)</div>
              <div style={{ color: 'var(--muted)', fontSize: 12.5 }}>
                Play a short warning sound when a pop-up notification appears.
              </div>
            </div>
            <button type="button" className="btn ghost sm" onClick={toggleSound}>
              {sound ? '🔊 Sound On' : '🔇 Sound Muted'}
            </button>
          </div>

          <div className="st-sub-setting">
            <div>
              <div style={{ fontWeight: 600, fontSize: 14 }}>When to Notify Me</div>
              <div style={{ color: 'var(--muted)', fontSize: 12.5 }}>
                Choose how sensitive your pop-up alerts should be.
              </div>
            </div>
            <div className="an-range-pills">
              <button
                type="button"
                className={'an-pill' + (level === 'critical' ? ' active' : '')}
                onClick={() => changeLevel('critical')}
              >
                Only Critical
              </button>
              <button
                type="button"
                className={'an-pill' + (level === 'high' ? ' active' : '')}
                onClick={() => changeLevel('high')}
              >
                Critical + High
              </button>
            </div>
          </div>
        </div>

        {/* 4. Password Change */}
        <ChangePassword token={token} />
      </div>
    </div>
  );
}
