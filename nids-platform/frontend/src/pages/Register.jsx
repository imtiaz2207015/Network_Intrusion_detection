import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api';
import GoogleButton from '../GoogleButton';
import AuthShell from '../AuthShell';

function strength(p) {
  let s = 0;
  if (p.length >= 8) s++;
  if (/[A-Z]/.test(p)) s++;
  if (/[0-9]/.test(p)) s++;
  if (/[^A-Za-z0-9]/.test(p)) s++;
  return s;
}
const COLORS = ['#f87171', '#fbbf24', '#38bdf8', '#34d399'];
const LABELS = ['Weak', 'Fair', 'Good', 'Strong'];

export default function Register() {
  const nav = useNavigate();
  const [f, setF] = useState({ username: '', email: '', password: '' });
  const [show, setShow] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const sc = strength(f.password);

  async function submit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await api('/register', { method: 'POST', body: f });
      nav('/login');
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Create your account" sub="Start detecting threats in minutes.">
      <GoogleButton onSuccess={() => nav('/')} onError={setError} />
      <div className="au-or">or register with email</div>
      <form onSubmit={submit}>
        <input className="au-input" placeholder="Username" value={f.username}
          autoComplete="username" onChange={set('username')} />
        <input className="au-input" type="email" placeholder="Email" value={f.email}
          autoComplete="email" onChange={set('email')} />
        <div className="au-pass">
          <input className="au-input" type={show ? 'text' : 'password'} placeholder="Password"
            value={f.password} autoComplete="new-password" onChange={set('password')} />
          <button type="button" className="au-eye" onClick={() => setShow(!show)}>
            {show ? 'Hide' : 'Show'}
          </button>
        </div>
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
        {error && <p className="au-err">{error}</p>}
        <button className="au-btn" disabled={busy || !f.username || !f.email || !f.password}>
          {busy ? 'Creating...' : 'Create account'}
        </button>
      </form>
      <p className="au-foot">Already registered? <Link to="/login">Sign in</Link></p>
    </AuthShell>
  );
}