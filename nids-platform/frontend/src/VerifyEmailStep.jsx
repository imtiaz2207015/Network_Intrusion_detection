import { useState, useEffect, useRef } from 'react';
import { api } from './api';
import { useAuth } from './AuthContext';
import AuthShell from './AuthShell';

export default function VerifyEmailStep({ email, onVerified, onBack }) {
  const { saveSession } = useAuth();
  const [digits, setDigits] = useState(['', '', '', '', '', '']);
  const [busy, setBusy] = useState(false);
  const [resending, setResending] = useState(false);
  const [cooldown, setCooldown] = useState(60);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const boxRefs = useRef([]);
  const errRef = useRef(null);

  useEffect(() => {
    const t = setTimeout(() => {
      if (boxRefs.current[0]) boxRefs.current[0].focus();
    }, 30);
    return () => clearTimeout(t);
  }, [email]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const id = setInterval(() => {
      setCooldown((c) => (c > 1 ? c - 1 : 0));
    }, 1000);
    return () => clearInterval(id);
  }, [cooldown]);

  useEffect(() => {
    if (error && errRef.current) {
      if (typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches) {
        errRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }
  }, [error]);

  function handleChange(idx, val) {
    const clean = String(val || '').replace(/\D/g, '');
    if (!clean) {
      setDigits((prev) => {
        const next = [...prev];
        next[idx] = '';
        return next;
      });
      return;
    }
    // If user typed or autofilled multiple digits into one box
    if (clean.length > 1) {
      const chars = clean.slice(0, 6).split('');
      setDigits((prev) => {
        const next = [...prev];
        for (let i = 0; i < chars.length && idx + i < 6; i++) {
          next[idx + i] = chars[i];
        }
        return next;
      });
      const focusIdx = Math.min(5, idx + clean.length);
      if (boxRefs.current[focusIdx]) boxRefs.current[focusIdx].focus();
      return;
    }

    const ch = clean.slice(-1);
    setDigits((prev) => {
      const next = [...prev];
      next[idx] = ch;
      return next;
    });
    if (idx < 5 && boxRefs.current[idx + 1]) {
      boxRefs.current[idx + 1].focus();
    }
  }

  function handleKeyDown(idx, e) {
    if (e.key === 'Backspace') {
      if (digits[idx]) {
        setDigits((prev) => {
          const next = [...prev];
          next[idx] = '';
          return next;
        });
      } else if (idx > 0 && boxRefs.current[idx - 1]) {
        e.preventDefault();
        setDigits((prev) => {
          const next = [...prev];
          next[idx - 1] = '';
          return next;
        });
        boxRefs.current[idx - 1].focus();
      }
    } else if (e.key === 'ArrowLeft' && idx > 0 && boxRefs.current[idx - 1]) {
      e.preventDefault();
      boxRefs.current[idx - 1].focus();
    } else if (e.key === 'ArrowRight' && idx < 5 && boxRefs.current[idx + 1]) {
      e.preventDefault();
      boxRefs.current[idx + 1].focus();
    }
  }

  function handlePaste(e) {
    e.preventDefault();
    const raw = (e.clipboardData?.getData('text') || '').replace(/\D/g, '').slice(0, 6);
    if (!raw) return;
    const next = ['', '', '', '', '', ''];
    for (let i = 0; i < raw.length; i++) {
      next[i] = raw[i];
    }
    setDigits(next);
    const focusIdx = Math.min(5, Math.max(0, raw.length - 1));
    if (boxRefs.current[focusIdx]) boxRefs.current[focusIdx].focus();
  }

  const code = digits.join('');

  async function onSubmit(e) {
    e.preventDefault();
    if (code.length !== 6) return;
    setError('');
    setInfo('');
    setBusy(true);
    try {
      const data = await api('/register/verify', {
        method: 'POST',
        body: { email, code },
      });
      if (data && data.token) {
        saveSession(data);
      }
      if (onVerified) onVerified(data);
    } catch (err) {
      setError(err.message || 'Verification failed');
    } finally {
      setBusy(false);
    }
  }

  async function onResend() {
    if (cooldown > 0 || resending || busy) return;
    setError('');
    setInfo('');
    setResending(true);
    try {
      const res = await api('/register/resend', {
        method: 'POST',
        body: { email },
      });
      setDigits(['', '', '', '', '', '']);
      setCooldown(60);
      setInfo(res.message || 'A new 6-digit code has been sent to your email.');
      if (boxRefs.current[0]) boxRefs.current[0].focus();
    } catch (err) {
      setError(err.message || 'Could not resend verification code');
    } finally {
      setResending(false);
    }
  }

  return (
    <AuthShell
      title="Verify your email"
      sub={`We sent a 6-digit code to ${email}`}
    >
      <form onSubmit={onSubmit}>
        <div
          className="au-otp-grid"
          role="group"
          aria-label="6-digit verification code"
          onPaste={handlePaste}
        >
          {digits.map((d, idx) => (
            <input
              key={idx}
              ref={(el) => { boxRefs.current[idx] = el; }}
              className="au-input au-otp-box mono"
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              autoComplete={idx === 0 ? 'one-time-code' : 'off'}
              maxLength={1}
              value={d}
              disabled={busy}
              aria-label={`Digit ${idx + 1}`}
              onChange={(e) => handleChange(idx, e.target.value)}
              onKeyDown={(e) => handleKeyDown(idx, e)}
            />
          ))}
        </div>

        <p className="au-hint" style={{ textAlign: 'center', marginBottom: 14 }}>
          Code expires in 10 minutes. Enter all 6 digits to verify.
        </p>

        {info && (
          <div role="status" className="au-ok">
            {info}
          </div>
        )}

        {error && (
          <div
            ref={errRef}
            role="alert"
            aria-live="assertive"
            className="au-err"
            style={{ fontWeight: 600 }}
          >
            {error}
          </div>
        )}

        <button
          type="submit"
          className="au-btn"
          disabled={busy || code.length !== 6}
        >
          {busy ? 'Verifying...' : 'Verify'}
        </button>

        <div className="au-otp-actions">
          <button
            type="button"
            className="btn ghost sm au-resend-btn"
            disabled={cooldown > 0 || resending || busy}
            onClick={onResend}
          >
            {resending
              ? 'Sending...'
              : cooldown > 0
                ? `Resend code (${cooldown}s)`
                : 'Resend code'}
          </button>

          <button
            type="button"
            className="au-link-btn"
            onClick={onBack}
            disabled={busy}
          >
            &larr; Use a different email
          </button>
        </div>
      </form>
    </AuthShell>
  );
}
