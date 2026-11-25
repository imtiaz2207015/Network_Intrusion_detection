import { useState, useEffect, useRef, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { api, sensorsApi, alertsApi } from '../api';
import {
  humanAge,
  formatTimestamp,
  formatTimeParts,
  formatAbsoluteTime,
  getTimeFormat24h,
  setTimeFormat24h,
} from '../format';
import {
  plainName,
  getPollIntervalMs,
  setPollIntervalMs,
  getAlertSoundEnabled,
  setAlertSoundEnabled,
} from '../utils';
import { useTheme } from '../theme';
import {
  getPopupLevel,
  setPopupLevel,
  AlertPopupCard,
} from '../notify';

const TABS = [
  { id: 'notifications', label: 'Notifications' },
  { id: 'protection', label: 'Protection' },
  { id: 'sensor', label: 'Sensor' },
  { id: 'preferences', label: 'Preferences' },
  { id: 'account', label: 'Account' },
];

const THEME_OPTIONS = [
  {
    value: 'dark',
    label: 'Dark',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
      </svg>
    ),
  },
  {
    value: 'light',
    label: 'Light',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
      </svg>
    ),
  },
  {
    value: 'system',
    label: 'System',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <rect x="2" y="3" width="20" height="14" rx="2" />
        <path d="M8 21h8M12 17v4" />
      </svg>
    ),
  },
];

const POLL_OPTIONS = [
  { value: 5000, label: '5s (Live)' },
  { value: 15000, label: '15s' },
  { value: 30000, label: '30s' },
  { value: 0, label: 'Paused' },
];

const PREVIEW_SAMPLE_ALERT = {
  id: null,
  type: 'BruteForce',
  src: '203.0.113.42',
  dport: '22',
  relTime: 'just now',
};

function playSubtleChime() {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(660, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.12);
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.26);
  } catch {
    /* ignore audio restrictions */
  }
}

function auditActionLabel(action) {
  const a = String(action || '').toLowerCase();
  if (a === 'blocked') return { text: 'Blocked', cls: 'blocked' };
  if (a.startsWith('skipped')) return { text: 'Skipped', cls: 'skipped' };
  return { text: action || 'Recorded', cls: 'skipped' };
}

export default function Settings() {
  const { user, token } = useAuth();
  const { hash } = useLocation();
  const themeBtnRefs = useRef([]);
  const [theme, setTheme] = useTheme();
  const [activeTab, setActiveTab] = useState(() =>
    hash === '#my-sensor' ? 'sensor' : 'notifications'
  );

  // Account
  const [meInfo, setMeInfo] = useState(null);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [pwErrors, setPwErrors] = useState({});
  const [pwBusy, setPwBusy] = useState(false);
  const [pwSuccess, setPwSuccess] = useState('');

  // Sensor & Notifications
  const [sensor, setSensor] = useState(null);
  const [sensorLoading, setSensorLoading] = useState(true);
  const [sensorErr, setSensorErr] = useState('');
  const [freshKey, setFreshKey] = useState('');
  const [confirmRegen, setConfirmRegen] = useState(false);
  const [regenBusy, setRegenBusy] = useState(false);
  const [savingEmailLevel, setSavingEmailLevel] = useState(false);
  const [savingPopupLevel, setSavingPopupLevel] = useState(false);
  const [popupLevel, setPopupLevelState] = useState(getPopupLevel);
  const [soundEnabled, setSoundEnabledState] = useState(getAlertSoundEnabled);
  const [notifSaved, setNotifSaved] = useState('');
  const [testToastVisible, setTestToastVisible] = useState(false);
  const [copiedField, setCopiedField] = useState('');

  // Protection & Auto-Block Audit Log
  const [prot, setProt] = useState({ mode: 'auto' });
  const [protLoading, setProtLoading] = useState(true);
  const [protSaving, setProtSaving] = useState(false);
  const [protMsg, setProtMsg] = useState('');
  const [protErr, setProtErr] = useState('');
  const [auditRows, setAuditRows] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditErr, setAuditErr] = useState('');

  // Preferences
  const [time24h, setTime24hState] = useState(getTimeFormat24h);
  const [pollMs, setPollMsState] = useState(getPollIntervalMs);
  const [prefSaved, setPrefSaved] = useState('');

  const protMsgTimerRef = useRef(null);
  const notifTimerRef = useRef(null);
  const prefTimerRef = useRef(null);
  const testToastTimerRef = useRef(null);

  const username = meInfo?.username || user?.username || 'User';
  const email = meInfo?.email || user?.email || '';
  const role = meInfo?.role || user?.role || 'viewer';
  const rawMemberSince = meInfo?.created_at || user?.created_at || user?.member_since || '';
  const memberSinceFormatted = rawMemberSince ? formatAbsoluteTime(rawMemberSince) : '—';
  const initial = (username || '?')[0].toUpperCase();
  const originUrl = typeof window !== 'undefined' ? window.location.origin : 'https://your-server-address';

  useEffect(() => {
    if (hash === '#my-sensor') {
      setActiveTab('sensor');
    }
  }, [hash]);

  useEffect(() => {
    let alive = true;
    api('/me', { token })
      .then((d) => {
        if (alive && d) setMeInfo(d);
      })
      .catch(() => {});
    return () => { alive = false; };
  }, [token]);

  useEffect(() => {
    let alive = true;
    async function loadSensor(first = false) {
      try {
        const d = await sensorsApi('/me', { token });
        if (!alive) return;
        setSensor(d);
        if (first) {
          setSensorLoading(false);
          if (d.popup_alert_level) {
            const synced = setPopupLevel(d.popup_alert_level);
            setPopupLevelState(synced);
          }
        }
        if (d.key) setFreshKey(d.key);
        setSensorErr('');
      } catch (e) {
        if (!alive) return;
        if (first) setSensorLoading(false);
        setSensorErr(e.message || 'Could not load sensor info.');
      }
    }
    loadSensor(true);
    const id = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      loadSensor(false);
    }, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [token]);

  useEffect(() => {
    let alive = true;
    alertsApi('/protection', { token })
      .then((d) => {
        if (!alive || !d) return;
        setProt({ mode: d.mode === 'manual' ? 'manual' : 'auto' });
      })
      .catch((e) => {
        if (alive) setProtErr(e.message || 'Could not load protection settings.');
      })
      .finally(() => {
        if (alive) setProtLoading(false);
      });
    return () => { alive = false; };
  }, [token]);

  const loadAudit = useCallback(async () => {
    setAuditLoading(true);
    setAuditErr('');
    try {
      const d = await alertsApi('/auto-block/audit', { token });
      setAuditRows(Array.isArray(d?.audit) ? d.audit : []);
    } catch (e) {
      setAuditErr(e.message || 'Could not load auto-block history.');
    } finally {
      setAuditLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (activeTab === 'protection') {
      loadAudit();
    }
  }, [activeTab, loadAudit]);

  function flashSaved(setter, timerRef, msg = 'Saved') {
    setter(msg);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setter(''), 2200);
  }

  async function handlePasswordSubmit(e) {
    e.preventDefault();
    setPwSuccess('');
    const nextErr = {};
    if (!currentPassword) nextErr.current = 'Current password is required.';
    if (!newPassword || newPassword.length < 8) {
      nextErr.new = 'New password must be at least 8 characters.';
    }
    if (confirmPassword !== newPassword) nextErr.confirm = 'Passwords do not match.';
    if (Object.keys(nextErr).length > 0) {
      setPwErrors(nextErr);
      return;
    }

    setPwErrors({});
    setPwBusy(true);
    try {
      await api('/password', {
        method: 'PUT',
        token,
        body: {
          current_password: currentPassword,
          new_password: newPassword,
        },
      });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setPwSuccess('Password updated');
    } catch (err) {
      const msg = err.message || 'Could not update password.';
      if (msg.toLowerCase().includes('current password')) {
        setPwErrors({ current: msg });
      } else if (msg.toLowerCase().includes('new password') || msg.toLowerCase().includes('8 characters')) {
        setPwErrors({ new: msg });
      } else {
        setPwErrors({ form: msg });
      }
    } finally {
      setPwBusy(false);
    }
  }

  async function handleEmailLevelChange(nextLevel) {
    setSavingEmailLevel(true);
    setSensorErr('');
    try {
      const updated = await sensorsApi('/me', {
        method: 'PATCH',
        token,
        body: { alert_email_level: nextLevel },
      });
      setSensor(updated);
      flashSaved(setNotifSaved, notifTimerRef);
    } catch (e2) {
      setSensorErr(e2.message || 'Could not update email alert level.');
    } finally {
      setSavingEmailLevel(false);
    }
  }

  async function handlePopupLevelChange(nextLevel) {
    const synced = setPopupLevel(nextLevel);
    setPopupLevelState(synced);
    setSavingPopupLevel(true);
    setSensorErr('');
    try {
      const updated = await sensorsApi('/me', {
        method: 'PATCH',
        token,
        body: { popup_alert_level: synced },
      });
      setSensor(updated);
    } catch {
      /* local preference is already saved */
    } finally {
      setSavingPopupLevel(false);
      flashSaved(setNotifSaved, notifTimerRef);
    }
  }

  function handleSoundToggle(nextVal) {
    setAlertSoundEnabled(nextVal);
    setSoundEnabledState(nextVal);
    if (nextVal) playSubtleChime();
    flashSaved(setNotifSaved, notifTimerRef);
  }

  function triggerTestPopup() {
    setTestToastVisible(true);
    if (soundEnabled) playSubtleChime();
    if (testToastTimerRef.current) clearTimeout(testToastTimerRef.current);
    testToastTimerRef.current = setTimeout(() => setTestToastVisible(false), 5500);
  }

  async function handleRegenerateKey() {
    setRegenBusy(true);
    setSensorErr('');
    try {
      const updated = await sensorsApi('/me/regenerate', {
        method: 'POST',
        token,
      });
      setSensor(updated);
      if (updated.key) setFreshKey(updated.key);
      setConfirmRegen(false);
    } catch (e2) {
      setSensorErr(e2.message || 'Could not regenerate sensor key.');
    } finally {
      setRegenBusy(false);
    }
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(label);
      setTimeout(() => setCopiedField(''), 2000);
    } catch {
      /* ignore */
    }
  }

  async function saveProtection(nextValues) {
    const nextMode = nextValues.mode === 'manual' ? 'manual' : 'auto';
    if (nextMode === prot.mode && !protErr) return;
    setProt({ mode: nextMode });
    setProtSaving(true);
    setProtErr('');
    setProtMsg('');
    try {
      const saved = await alertsApi('/protection', {
        method: 'PUT',
        token,
        body: { mode: nextMode },
      });
      setProt({ mode: saved.mode === 'manual' ? 'manual' : 'auto' });
      flashSaved(setProtMsg, protMsgTimerRef);
    } catch (e2) {
      setProtErr(e2.message || 'Could not save protection settings.');
    } finally {
      setProtSaving(false);
    }
  }

  function handleTimeFormatChange(use24h) {
    setTimeFormat24h(use24h);
    setTime24hState(use24h);
    flashSaved(setPrefSaved, prefTimerRef);
  }

  function handlePollChange(nextMs) {
    const saved = setPollIntervalMs(nextMs);
    setPollMsState(saved);
    flashSaved(setPrefSaved, prefTimerRef);
  }

  function handleThemeKeyDown(e, idx) {
    let nextIdx = -1;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      nextIdx = (idx + 1) % THEME_OPTIONS.length;
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      nextIdx = (idx - 1 + THEME_OPTIONS.length) % THEME_OPTIONS.length;
    } else if (e.key === 'Home') {
      nextIdx = 0;
    } else if (e.key === 'End') {
      nextIdx = THEME_OPTIONS.length - 1;
    }
    if (nextIdx !== -1) {
      e.preventDefault();
      setTheme(THEME_OPTIONS[nextIdx].value);
      themeBtnRefs.current[nextIdx]?.focus();
    }
  }

  const isSensorOnline = !!(sensor && sensor.online);
  const lastSeenText = !sensor
    ? '—'
    : sensor.age !== null && sensor.age !== undefined
      ? humanAge(sensor.age)
      : sensor.last_seen_at
        ? formatTimestamp(sensor.last_seen_at)
        : 'Never connected';

  const keyPlaceholder = freshKey || (sensor?.key_prefix ? `${sensor.key_prefix}••••••••` : '<YOUR_SENSOR_KEY>');
  const psCmd = `$env:NIDS_SERVER_URL="${originUrl}"\n$env:SENSOR_KEY="${keyPlaceholder}"`;
  const shCmd = `export NIDS_SERVER_URL="${originUrl}"\nexport SENSOR_KEY="${keyPlaceholder}"`;

  const regenModal = confirmRegen && (
    <div
      className="blk-modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget && !regenBusy) setConfirmRegen(false);
      }}
    >
      <div className="card blk-modal" role="dialog" aria-modal="true" aria-labelledby="regen-modal-title">
        <div className="blk-modal-head">
          <div>
            <span className="blk-modal-kicker">Sensor authentication</span>
            <h3 id="regen-modal-title">Regenerate sensor key?</h3>
          </div>
          <button
            type="button"
            className="btn ghost sm blk-close-btn"
            onClick={() => setConfirmRegen(false)}
            disabled={regenBusy}
            aria-label="Close dialog"
          >
            ✕
          </button>
        </div>
        <div className="blk-modal-body">
          <p className="blk-modal-note" style={{ borderLeftColor: 'var(--warn)' }}>
            Your current sensor key (<b className="mono">{sensor?.key_prefix}...</b>) will stop working immediately.
            Update <code className="mono">SENSOR_KEY</code> on your sensor with the new key.
          </p>
          <div className="blk-modal-actions">
            <button
              type="button"
              className="btn ghost sm"
              onClick={() => setConfirmRegen(false)}
              disabled={regenBusy}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn sm"
              onClick={handleRegenerateKey}
              disabled={regenBusy}
            >
              {regenBusy ? 'Regenerating...' : 'Regenerate key'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  const testToastPortal = testToastVisible && createPortal(
    <div className="st-test-toast-wrap" role="status" aria-live="polite">
      <AlertPopupCard
        alert={PREVIEW_SAMPLE_ALERT}
        onDismiss={() => setTestToastVisible(false)}
      />
    </div>,
    document.body
  );

  return (
    <div className="st-page">
      {/* Page Header */}
      <div className="st-page-header">
        <div>
          <h2>Settings</h2>
          <p className="band-sub">
            Manage alert notifications, automatic protection, sensor connection, and display preferences.
          </p>
        </div>
      </div>

      {/* Horizontal Tab Bar */}
      <div className="st-tabs" role="tablist" aria-label="Settings sections">
        {TABS.map((t) => {
          const isActive = activeTab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              className={'st-tab' + (isActive ? ' active' : '')}
              onClick={() => setActiveTab(t.id)}
            >
              <span>{t.label}</span>
              {t.id === 'sensor' && (
                <span
                  className={'st-tab-dot ' + (isSensorOnline ? 'online' : 'offline')}
                  aria-label={isSensorOnline ? 'Sensor online' : 'Sensor offline'}
                />
              )}
            </button>
          );
        })}
      </div>

      {/* TAB 1: Notifications */}
      {activeTab === 'notifications' && (
        <section className="st-sec" aria-label="Notification settings">
          <div className="st-sec-head-row">
            <h3 className="st-sec-title">Alert Notifications</h3>
            {notifSaved && (
              <span className="badge mono st-saved-pill">✓ {notifSaved}</span>
            )}
          </div>

          {sensorErr && (
            <div className="help-banner err" role="alert">
              <span>!</span>
              <span>{sensorErr}</span>
            </div>
          )}

          <div className="st-alerts-grid">
            <div className="card st-equal-tile">
              <div className="st-tile-head">
                <label htmlFor="sensor-email-level" className="st-tile-title">
                  Email alerts
                </label>
                <p className="st-tile-sub">
                  Send email to <span className="mono">{email || 'your account'}</span> when threats are detected.
                </p>
              </div>
              <select
                id="sensor-email-level"
                className="input st-tile-select"
                value={sensor?.alert_email_level || 'critical'}
                disabled={sensorLoading || savingEmailLevel}
                onChange={(e) => handleEmailLevelChange(e.target.value)}
              >
                <option value="critical">Critical only</option>
                <option value="critical_high">Critical and High</option>
                <option value="off">Off</option>
              </select>
            </div>

            <div className="card st-equal-tile">
              <div className="st-tile-head">
                <label htmlFor="sensor-popup-level" className="st-tile-title">
                  Pop-up alerts
                </label>
                <p className="st-tile-sub">
                  Show live alert banners in the top-right corner as threats arrive.
                </p>
              </div>
              <select
                id="sensor-popup-level"
                className="input st-tile-select"
                value={popupLevel}
                disabled={savingPopupLevel}
                onChange={(e) => handlePopupLevelChange(e.target.value)}
              >
                <option value="critical">Critical only</option>
                <option value="critical_high">Critical and High</option>
                <option value="off">Off</option>
              </select>
            </div>
          </div>

          <div className="card st-pref-row">
            <div>
              <div className="st-appearance-label">Alert sound chime</div>
              <p className="st-appearance-sub">
                Play a subtle sound when a live pop-up alert appears.
              </p>
            </div>
            <div className="st-seg-inline" role="radiogroup" aria-label="Alert sound">
              <button
                type="button"
                role="radio"
                aria-checked={soundEnabled}
                className={'st-seg-btn' + (soundEnabled ? ' active' : '')}
                onClick={() => handleSoundToggle(true)}
              >
                On
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={!soundEnabled}
                className={'st-seg-btn' + (!soundEnabled ? ' active' : '')}
                onClick={() => handleSoundToggle(false)}
              >
                Off
              </button>
            </div>
          </div>

          <div className="card st-preview-card">
            <div className="st-preview-head">
              <div>
                <div className="st-appearance-label">Pop-up preview</div>
                <p className="st-appearance-sub">Test how incoming alerts look and sound in your browser.</p>
              </div>
              <button
                type="button"
                className="btn ghost sm"
                onClick={triggerTestPopup}
              >
                Send test pop-up
              </button>
            </div>
            <AlertPopupCard alert={PREVIEW_SAMPLE_ALERT} preview />
          </div>
        </section>
      )}

      {/* TAB 2: Protection */}
      {activeTab === 'protection' && (
        <section className="st-sec" aria-label="Protection settings">
          <div className="st-sec-head-row">
            <h3 id="protection-mode-heading" className="st-sec-title">Automatic Protection</h3>
            {protMsg && (
              <span className="badge mono st-saved-pill">✓ {protMsg}</span>
            )}
          </div>

          <div className="card st-prot-card">
            {protErr && (
              <div className="help-banner err" role="alert" style={{ marginBottom: 12 }}>
                <span>!</span>
                <span>{protErr}</span>
              </div>
            )}

            <div
              className="st-prot-seg"
              role="radiogroup"
              aria-labelledby="protection-mode-heading"
            >
              <button
                type="button"
                role="radio"
                aria-checked={prot.mode === 'auto'}
                disabled={protLoading || protSaving}
                className={'st-prot-seg-btn' + (prot.mode === 'auto' ? ' active' : '')}
                onClick={() => saveProtection({ mode: 'auto' })}
              >
                <span className="st-prot-seg-label">Auto</span>
                <span className="st-prot-seg-hint">Recommended</span>
              </button>

              <button
                type="button"
                role="radio"
                aria-checked={prot.mode === 'manual'}
                disabled={protLoading || protSaving}
                className={'st-prot-seg-btn' + (prot.mode === 'manual' ? ' active' : '')}
                onClick={() => saveProtection({ mode: 'manual' })}
              >
                <span className="st-prot-seg-label">Manual</span>
                <span className="st-prot-seg-hint">Review before blocking</span>
              </button>
            </div>

            {prot.mode === 'auto' ? (
              <div className="st-prot-body">
                <div className="st-prot-lines">
                  <div className="st-prot-line">First offense: blocked for 1 hour</div>
                  <div className="st-prot-line">Second offense: blocked for 24 hours</div>
                  <div className="st-prot-line">Repeat offender: blocked for 7 days</div>
                </div>
                <p className="st-prot-note-line">
                  Your own device, router/gateway, and local loopback are automatically protected by the system.
                </p>
              </div>
            ) : (
              <div className="st-prot-body">
                <p className="st-prot-manual-line">
                  Automatic blocking is paused. You can still block any suspicious IP manually from the Alerts page.
                </p>
              </div>
            )}
          </div>

          {/* Auto-Block Activity Log (uses existing GET /api/alerts/auto-block/audit) */}
          <div className="card st-audit-card">
            <div className="st-audit-head">
              <div>
                <div className="st-appearance-label">Auto-Block Activity Log</div>
                <p className="st-appearance-sub">Recent automatic protection decisions made by the system.</p>
              </div>
              <button
                type="button"
                className="btn ghost sm"
                onClick={loadAudit}
                disabled={auditLoading}
              >
                {auditLoading ? 'Refreshing...' : 'Refresh'}
              </button>
            </div>

            {auditErr && (
              <div className="help-banner err" role="alert" style={{ margin: '12px 18px' }}>
                <span>!</span>
                <span>{auditErr}</span>
              </div>
            )}

            {!auditLoading && auditRows.length === 0 ? (
              <div className="st-audit-empty">
                No automatic block decisions recorded yet.
              </div>
            ) : (
              <div className="st-audit-list">
                {auditRows.slice(0, 15).map((row) => {
                  const badge = auditActionLabel(row.action);
                  const tp = formatTimeParts(row.created_at);
                  return (
                    <div key={row.id} className="st-audit-row">
                      <span className={'st-audit-badge ' + badge.cls}>{badge.text}</span>
                      <div className="st-audit-main">
                        <div className="st-audit-top">
                          <span className="mono st-audit-ip">{row.ip || '—'}</span>
                          <span className="st-audit-type">{plainName(row.attack_type)}</span>
                        </div>
                        {row.reason && <div className="st-audit-reason">{row.reason}</div>}
                      </div>
                      <div className="st-audit-time mono" title={formatAbsoluteTime(row.created_at)}>
                        <span>{tp.date}</span>
                        {tp.age && <small>{tp.age}</small>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </section>
      )}

      {/* TAB 3: Sensor */}
      {activeTab === 'sensor' && (
        <section id="my-sensor" className="st-sec" aria-label="Sensor settings">
          <h3 className="st-sec-title">Network Sensor</h3>

          {sensorErr && (
            <div className="help-banner err" role="alert">
              <span>!</span>
              <span>{sensorErr}</span>
            </div>
          )}

          <div className="st-sensor-grid">
            <div className="card st-sensor-tile">
              <span className="st-sensor-label">Status</span>
              <div className="st-sensor-value">
                <span
                  className={'st-status-dot ' + (isSensorOnline ? 'online' : 'offline')}
                  aria-hidden="true"
                />
                <span>{isSensorOnline ? 'Online' : 'Offline'}</span>
              </div>
            </div>

            <div className="card st-sensor-tile">
              <span className="st-sensor-label">Last seen</span>
              <div
                className="st-sensor-value"
                title={sensor?.last_seen_at ? formatAbsoluteTime(sensor.last_seen_at) : ''}
              >
                {lastSeenText}
              </div>
            </div>

            <div className="card st-sensor-tile">
              <span className="st-sensor-label">Sensor key</span>
              <div className="st-sensor-key-row">
                <code className="mono st-sensor-value">
                  {sensor?.key_prefix ? `${sensor.key_prefix}...` : '—'}
                </code>
                <button
                  type="button"
                  className="btn ghost sm"
                  onClick={() => setConfirmRegen(true)}
                  disabled={sensorLoading}
                >
                  Regenerate
                </button>
              </div>
            </div>
          </div>

          {freshKey && (
            <div className="card st-sensor-key-box" role="region" aria-label="New sensor key">
              <div className="st-fresh-key-head">
                <strong style={{ color: 'var(--warn)', fontSize: 13 }}>
                  Copy this key now — it will not be shown again.
                </strong>
                <button
                  type="button"
                  className="btn sm"
                  onClick={() => copyText(freshKey, 'key')}
                >
                  {copiedField === 'key' ? '✓ Copied key' : 'Copy key'}
                </button>
              </div>
              <div className="mono st-fresh-key-code">{freshKey}</div>
            </div>
          )}

          {/* Quick Connect Guide (always accessible) */}
          <div className="card st-connect-card">
            <div className="st-connect-head">
              <div>
                <div className="st-appearance-label">Quick connect</div>
                <p className="st-appearance-sub">
                  Point your Raspberry Pi or Windows sensor to this server with these environment variables.
                </p>
              </div>
            </div>

            <div className="st-connect-block">
              <div className="st-connect-label-row">
                <small className="mono">Linux / Raspberry Pi</small>
                <button
                  type="button"
                  className="btn ghost sm st-copy-sm"
                  onClick={() => copyText(shCmd, 'sh')}
                >
                  {copiedField === 'sh' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <pre className="mono st-fresh-key-pre">{shCmd}</pre>
            </div>

            <div className="st-connect-block">
              <div className="st-connect-label-row">
                <small className="mono">Windows PowerShell</small>
                <button
                  type="button"
                  className="btn ghost sm st-copy-sm"
                  onClick={() => copyText(psCmd, 'ps')}
                >
                  {copiedField === 'ps' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <pre className="mono st-fresh-key-pre">{psCmd}</pre>
            </div>
          </div>
        </section>
      )}

      {/* TAB 4: Preferences */}
      {activeTab === 'preferences' && (
        <section className="st-sec" aria-label="Display preferences">
          <div className="st-sec-head-row">
            <h3 className="st-sec-title">Display &amp; Live Updates</h3>
            {prefSaved && (
              <span className="badge mono st-saved-pill">✓ {prefSaved}</span>
            )}
          </div>

          {/* Theme */}
          <div className="card st-appearance-card">
            <div className="st-appearance-text">
              <div id="st-theme-heading" className="st-appearance-label">Theme</div>
              <p className="st-appearance-sub">Choose how SentinelIQ looks on this device.</p>
            </div>

            <div
              className="st-theme-seg"
              role="radiogroup"
              aria-labelledby="st-theme-heading"
            >
              {THEME_OPTIONS.map((opt, idx) => {
                const selected = theme === opt.value;
                return (
                  <button
                    key={opt.value}
                    ref={(el) => { themeBtnRefs.current[idx] = el; }}
                    type="button"
                    role="radio"
                    aria-checked={selected}
                    tabIndex={selected ? 0 : -1}
                    className={'st-theme-seg-btn' + (selected ? ' active' : '')}
                    onClick={() => setTheme(opt.value)}
                    onKeyDown={(e) => handleThemeKeyDown(e, idx)}
                  >
                    {opt.icon}
                    <span>{opt.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Time Format */}
          <div className="card st-pref-row">
            <div>
              <div className="st-appearance-label">Time format</div>
              <p className="st-appearance-sub">
                Choose how timestamps appear across Alerts, Blocked IPs, and AI Assistant.
              </p>
            </div>
            <div className="st-seg-inline" role="radiogroup" aria-label="Time format">
              <button
                type="button"
                role="radio"
                aria-checked={!time24h}
                className={'st-seg-btn' + (!time24h ? ' active' : '')}
                onClick={() => handleTimeFormatChange(false)}
              >
                12-hour (06:51 PM)
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={time24h}
                className={'st-seg-btn' + (time24h ? ' active' : '')}
                onClick={() => handleTimeFormatChange(true)}
              >
                24-hour (18:51)
              </button>
            </div>
          </div>

          {/* Live Refresh Speed */}
          <div className="card st-pref-row">
            <div>
              <div className="st-appearance-label">Live refresh speed</div>
              <p className="st-appearance-sub">
                How often Dashboard and Alerts automatically check for new threats.
              </p>
            </div>
            <div className="st-seg-inline" role="radiogroup" aria-label="Live refresh speed">
              {POLL_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  role="radio"
                  aria-checked={pollMs === opt.value}
                  className={'st-seg-btn' + (pollMs === opt.value ? ' active' : '')}
                  onClick={() => handlePollChange(opt.value)}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* TAB 5: Account */}
      {activeTab === 'account' && (
        <section className="st-sec" aria-label="Account settings">
          <h3 className="st-sec-title">Account &amp; Security</h3>

          <div className="card st-profile-summary-card">
            <div className="st-acc-left">
              <div className="st-avatar">{initial}</div>
              <div className="st-acc-summary">
                <div className="st-acc-title-line">
                  <span className="st-acc-name">{username}</span>
                  <span className="st-role-badge">{role}</span>
                </div>
                <div className="st-acc-sub">{email || 'Signed in to SentinelIQ'}</div>
              </div>
            </div>
            <div className="st-kv-grid">
              <div className="st-kv-row">
                <span className="st-kv-label">Username</span>
                <span className="mono st-kv-val">{username}</span>
              </div>
              <div className="st-kv-row">
                <span className="st-kv-label">Email</span>
                <span className="mono st-kv-val">{email || '—'}</span>
              </div>
              <div className="st-kv-row">
                <span className="st-kv-label">Role</span>
                <span className="st-kv-val" style={{ textTransform: 'capitalize' }}>{role}</span>
              </div>
              <div className="st-kv-row">
                <span className="st-kv-label">Member since</span>
                <span className="mono st-kv-val">{memberSinceFormatted}</span>
              </div>
            </div>
          </div>

          <div className="card st-pw-card">
            <div className="st-appearance-label" style={{ marginBottom: 4 }}>Change password</div>
            <p className="st-appearance-sub" style={{ marginBottom: 14 }}>
              Use at least 8 characters to keep your account secure.
            </p>
            <form className="st-pw-form" onSubmit={handlePasswordSubmit} noValidate>
              <div className="st-pw-field">
                <label htmlFor="st-cur-pw">Current password</label>
                <input
                  id="st-cur-pw"
                  type="password"
                  className="input"
                  autoComplete="current-password"
                  value={currentPassword}
                  disabled={pwBusy}
                  onChange={(e) => {
                    setCurrentPassword(e.target.value);
                    setPwSuccess('');
                    if (pwErrors.current) setPwErrors((p) => ({ ...p, current: '' }));
                  }}
                />
                {pwErrors.current && (
                  <span className="st-field-err" role="alert">{pwErrors.current}</span>
                )}
              </div>

              <div className="st-pw-two">
                <div className="st-pw-field">
                  <label htmlFor="st-new-pw">New password</label>
                  <input
                    id="st-new-pw"
                    type="password"
                    className="input"
                    autoComplete="new-password"
                    value={newPassword}
                    disabled={pwBusy}
                    onChange={(e) => {
                      setNewPassword(e.target.value);
                      setPwSuccess('');
                      if (pwErrors.new) setPwErrors((p) => ({ ...p, new: '' }));
                    }}
                  />
                  {pwErrors.new && (
                    <span className="st-field-err" role="alert">{pwErrors.new}</span>
                  )}
                </div>

                <div className="st-pw-field">
                  <label htmlFor="st-confirm-pw">Confirm new password</label>
                  <input
                    id="st-confirm-pw"
                    type="password"
                    className="input"
                    autoComplete="new-password"
                    value={confirmPassword}
                    disabled={pwBusy}
                    onChange={(e) => {
                      setConfirmPassword(e.target.value);
                      setPwSuccess('');
                      if (pwErrors.confirm) setPwErrors((p) => ({ ...p, confirm: '' }));
                    }}
                  />
                  {pwErrors.confirm && (
                    <span className="st-field-err" role="alert">{pwErrors.confirm}</span>
                  )}
                </div>
              </div>

              {pwErrors.form && (
                <span className="st-field-err" role="alert">{pwErrors.form}</span>
              )}

              <div className="st-pw-actions">
                <button type="submit" className="btn sm" disabled={pwBusy}>
                  {pwBusy ? 'Updating...' : 'Update password'}
                </button>
                {pwSuccess && (
                  <span className="st-pw-success" role="status">
                    ✓ {pwSuccess}
                  </span>
                )}
              </div>
            </form>
          </div>
        </section>
      )}

      {regenModal && createPortal(regenModal, document.body)}
      {testToastPortal}
    </div>
  );
}
