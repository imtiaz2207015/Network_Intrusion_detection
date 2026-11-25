import { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { api } from '../api';
import { consumeNextPath } from '../utils';
import GoogleButton from '../GoogleButton';
import AuthShell from '../AuthShell';
import VerifyEmailStep from '../VerifyEmailStep';

function strength(p) {
  let s = 0;
  if (p.length >= 8) s++;
  if (/[A-Z]/.test(p)) s++;
  if (/[0-9]/.test(p)) s++;
  if (/[^A-Za-z0-9]/.test(p)) s++;
  return s;
}
const COLORS = ['var(--danger)', 'var(--high)', 'var(--warn)', 'var(--accent)'];
const LABELS = ['Weak', 'Fair', 'Good', 'Strong'];

export default function Register() {
  const nav = useNavigate();
  const location = useLocation();
  const [f, setF] = useState({ username: '', email: '', password: '' });
  const [show, setShow] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [verifyEmail, setVerifyEmail] = useState('');
  const errRef = useRef(null);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const sc = strength(f.password);
  const hasInvalidUsernameChar = /[@.\s]/.test(f.username);

  useEffect(() => {
    if (error && errRef.current) {
      if (typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches) {
        errRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }
  }, [error]);

  function finishRegisterRedirect() {
    nav(consumeNextPath(location.search), { replace: true });
  }

  async function submit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const res = await api('/register', { method: 'POST', body: f });
      if (res && res.verify) {
        setVerifyEmail(res.email || f.email.trim().toLowerCase());
      } else {
        nav(`/login${location.search || ''}`);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (verifyEmail) {
    return (
      <VerifyEmailStep
        email={verifyEmail}
        onVerified={finishRegisterRedirect}
        onBack={() => {
          setVerifyEmail('');
          setError('');
        }}
      />
    );
  }

  return (
    <AuthShell title="Create your account" sub="Start detecting threats in minutes.">
      <GoogleButton onSuccess={finishRegisterRedirect} onError={setError} />
      <div className="au-or">or register with email</div>
      <form onSubmit={submit}>
        <input className="au-input" placeholder="Username" value={f.username}
          autoComplete="username" onChange={set('username')} />
        <p className="au-hint" style={{ marginTop: -6, marginBottom: hasInvalidUsernameChar ? 4 : 12 }}>
          3-20 letters, numbers or _ (no spaces, no @)
        </p>
        {hasInvalidUsernameChar && (
          <p className="au-hint" role="alert" style={{ color: 'var(--danger)', fontWeight: 600, marginBottom: 12 }}>
            Username cannot contain &quot;@&quot;, &quot;.&quot; or spaces.
          </p>
        )}
        <input className="au-input" type="email" placeholder="Email" value={f.email}
          autoComplete="email" onChange={set('email')} />
        <div className="au-pass">
          <input className="au-input" type={show ? 'text' : 'password'} placeholder="Password"
            value={f.password} autoComplete="new-password" onChange={set('password')} />
          <button type="button" className="au-eye" onClick={() => setShow(!show)}>
            {show ? 'Hide' : 'Show'}
          </button>
        </div>
        <p className="au-hint" style={{ marginTop: -6, marginBottom: f.password ? 8 : 12 }}>
          At least 8 characters, letters and numbers
        </p>
        {f.password && (
          <>
            <div className="au-meter">
              {[0, 1, 2, 3].map((i) => (
                <i key={i} style={{ background: i < sc ? COLORS[sc - 1] : undefined }} />
              ))}
            </div>
            <p className="au-hint">
              Strength: <b style={{ color: COLORS[Math.max(0, sc - 1)] }}>{LABELS[Math.max(0, sc - 1)]}</b>
              {sc < 3 && ' - use 8+ characters, a capital letter and a number'}
            </p>
          </>
        )}
        {error && (
          <div ref={errRef} role="alert" aria-live="assertive" className="au-err" style={{ fontWeight: 600 }}>
            {error}
          </div>
        )}
        <button className="au-btn" disabled={busy || !f.username || !f.email || !f.password}>
          {busy ? 'Creating...' : 'Create account'}
        </button>
      </form>
      <p className="au-foot">Already registered? <Link to={`/login${location.search || ''}`}>Sign in</Link></p>
    </AuthShell>
  );
}
