import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { api } from '../api';

export default function ChangePassword({ token }) {
  const [open, setOpen] = useState(false);
  const [cur, setCur] = useState('');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [code, setCode] = useState('');
  const [step, setStep] = useState(1);
  const [sentTo, setSentTo] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [ok, setOk] = useState('');

  useEffect(() => {
    if (!open) return;
    const onKey = (e) => e.key === 'Escape' && close();
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [open]);

  function reset() {
    setCur(''); setPw(''); setPw2(''); setCode('');
    setStep(1); setSentTo(''); setErr(''); setOk(''); setBusy(false);
  }

  function close() {
    setOpen(false);
    reset();
  }

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

  const modal = open && (
    <div className="cp-overlay" onClick={close}>
      <div className="cp-modal" onClick={(e) => e.stopPropagation()}>
        <button className="cp-x" onClick={close} aria-label="Close">✕</button>
        <div className="stat-label" style={{ marginBottom: 4 }}>Email-Verified Password Change</div>
        <div className="mono" style={{ fontSize: 11.5, color: 'var(--accent)', marginBottom: 14 }}>
          STEP {step} OF 2 · {step === 1 ? 'VERIFY CREDENTIALS' : 'ENTER EMAIL CODE'}
        </div>

        {step === 1 ? (
          <form onSubmit={sendCode} style={{ display: 'grid', gap: 10 }}>
            <input className="input" type="password" placeholder="Current password"
              autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
            <input className="input" type="password" placeholder="New password (8+ chars, letters & numbers)"
              autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
            <input className="input" type="password" placeholder="Confirm new password"
              autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
            <button className="btn sm" type="submit" disabled={busy}>
              {busy ? 'Sending code...' : 'Send verification code →'}
            </button>
          </form>
        ) : (
          <form onSubmit={confirm} style={{ display: 'grid', gap: 10 }}>
            <p style={{ margin: 0, fontSize: 13.5, color: 'var(--muted)', lineHeight: 1.5 }}>
              We sent a 6-digit verification code to <b style={{ color: 'var(--text)' }}>{sentTo}</b>. It expires in 10 minutes.
            </p>
            <input className="input mono" inputMode="numeric" maxLength={6} placeholder="000000"
              style={{ fontSize: 20, letterSpacing: 6, textAlign: 'center' }}
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
        {ok && <p style={{ color: 'var(--ok)', fontSize: 13, marginTop: 12 }}>{ok}</p>}
      </div>
    </div>
  );

  return (
    <div className="card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
      <div>
        <div style={{ fontWeight: 600 }}>Account Password</div>
        <div style={{ color: 'var(--muted)', fontSize: 13, marginTop: 2 }}>Update password with 6-digit email verification.</div>
      </div>
      <button className="btn sm" onClick={() => setOpen(true)}>Change password</button>
      {modal && createPortal(modal, document.body)}
    </div>
  );
}
