import { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { consumeNextPath, sanitizeNextPath } from '../utils';
import GoogleButton from '../GoogleButton';
import AuthShell from '../AuthShell';
import VerifyEmailStep from '../VerifyEmailStep';

export default function Login() {
  const { login } = useAuth();
  const nav = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [verifyEmail, setVerifyEmail] = useState('');
  const errRef = useRef(null);

  // Persist ?next= into sessionStorage if present and valid
  useEffect(() => {
    try {
      const params = new URLSearchParams(location.search);
      const qNext = params.get('next');
      if (qNext) {
        const clean = sanitizeNextPath(qNext);
        if (clean !== '/') sessionStorage.setItem('nids_next_path', clean);
      }
    } catch { /* ignore */ }
  }, [location.search]);

  // Clear welcome flag so a fresh login always triggers the post-login radar handshake
  useEffect(() => {
    try {
      Object.keys(sessionStorage).forEach((k) => {
        if (k.startsWith('nids_welcomed')) sessionStorage.removeItem(k);
      });
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    if (error && errRef.current) {
      if (typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches) {
        errRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }
  }, [error]);

  function finishLoginRedirect() {
    nav(consumeNextPath(location.search), { replace: true });
  }

  async function submit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await login(email.trim(), password);
      finishLoginRedirect();
    } catch (err) {
      if (err.status === 403 && err.verify) {
        setVerifyEmail(err.email || email.trim().toLowerCase());
      } else {
        setError(err.message);
      }
    } finally {
      setBusy(false);
    }
  }

  if (verifyEmail) {
    return (
      <VerifyEmailStep
        email={verifyEmail}
        onVerified={finishLoginRedirect}
        onBack={() => {
          setVerifyEmail('');
          setError('');
        }}
      />
    );
  }

  return (
    <AuthShell title="Welcome back" sub="Sign in to monitor your network in real time.">
      <GoogleButton onSuccess={finishLoginRedirect} onError={setError} />
      <div className="au-or">or continue with email</div>
      <form onSubmit={submit}>
        <input className="au-input" type="email" placeholder="Email" value={email}
          autoComplete="email" onChange={(e) => setEmail(e.target.value)} />
        <div className="au-pass">
          <input className="au-input" type={show ? 'text' : 'password'} placeholder="Password"
            value={password} autoComplete="current-password"
            onChange={(e) => setPassword(e.target.value)} />
          <button type="button" className="au-eye" onClick={() => setShow(!show)}>
            {show ? 'Hide' : 'Show'}
          </button>
        </div>
        <p className="au-forgot"><Link to="/forgot-password">Forgot password?</Link></p>
        {error && (
          <div ref={errRef} role="alert" aria-live="assertive" className="au-err" style={{ fontWeight: 600 }}>
            {error}
          </div>
        )}
        <button className="au-btn" disabled={busy || !email || !password}>
          {busy ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
      <p className="au-foot">No account? <Link to={`/register${location.search || ''}`}>Create one</Link></p>
    </AuthShell>
  );
}
