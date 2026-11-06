import { useState } from 'react';
import { api } from '../api';

export default function ChangePassword({ token }) {
  const [cur, setCur] = useState('');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [code, setCode] = useState('');
  const [step, setStep] = useState(1);
  const [sentTo, setSentTo] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [ok, setOk] = useState('');

  async function sendCode(e) {
    e.preventDefault();
    setErr(''); setOk('');
    if (pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)) {
      setErr('New password: at least 8 characters with letters and numbers');
      return;
    }
    if (pw !== pw2) { setErr('New passwords do not match'); return; }
    setBusy(true);
    try {
      const r = await api('/change-password/request', {
        method: 'POST', token,
        body: { current_password: cur, new_password: pw },
      });
      setSentTo(r.email || 'your email');
      setStep(2);
    } catch (e2) {
      setErr(e2.message);
    }
    setBusy(false);
  }

  async function confirm(e) {
    e.preventDefault();
    setErr(''); setOk('');
    setBusy(true);
    try {
      await api('/change-password/confirm', {
        method: 'POST', token, body: { code: code.trim() },
      });
      setOk('Password changed.');
      setCur(''); setPw(''); setPw2(''); setCode(''); setStep(1);
    } catch (e2) {
      setErr(e2.message);
    }
    setBusy(false);
  }

  function back() { setStep(1); setCode(''); setErr(''); }

  return (
    <div className="card">
      <div className="stat-label" style={{ marginBottom: 12 }}>Change password</div>
      {step === 1 ? (
        <form onSubmit={sendCode} style={{ display: 'grid', gap: 10 }}>
          <input className="input" type="password" placeholder="Current password"
            autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
          <input className="input" type="password" placeholder="New password"
            autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
          <input className="input" type="password" placeholder="Confirm new password"
            autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
          <button className="btn sm" type="submit" disabled={busy}>
            {busy ? 'Sending code...' : 'Send verification code'}
          </button>
        </form>
      ) : (
        <form onSubmit={confirm} style={{ display: 'grid', gap: 10 }}>
          <p style={{ margin: 0, fontSize: 14, color: 'var(--muted)' }}>
            We sent a 6-digit code to {sentTo}. It expires in 10 minutes.
          </p>
          <input className="input" inputMode="numeric" maxLength={6} placeholder="6-digit code"
            autoComplete="one-time-code" value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} />
          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn sm" type="submit" disabled={busy || code.length !== 6}>
              {busy ? 'Checking...' : 'Confirm change'}
            </button>
            <button className="btn ghost sm" type="button" onClick={back} disabled={busy}>Back</button>
          </div>
        </form>
      )}
      {err && <p style={{ color: 'var(--danger)', fontSize: 13, marginTop: 12 }}>{err}</p>}
      {ok && <p style={{ color: 'var(--accent)', fontSize: 13, marginTop: 12 }}>{ok}</p>}
    </div>
  );
}