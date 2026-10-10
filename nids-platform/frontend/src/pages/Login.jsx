import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import GoogleButton from '../GoogleButton';
import AuthShell from '../AuthShell';

export default function Login() {
  const { login } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await login(email.trim(), password);
      nav('/');
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Welcome back" sub="Sign in to monitor your network.">
      <GoogleButton onSuccess={() => nav('/')} onError={setError} />
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
        {error && <p className="au-err">{error}</p>}
        <button className="au-btn" disabled={busy || !email || !password}>
          {busy ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
      <p className="au-foot">No account? <Link to="/register">Create one</Link></p>
    </AuthShell>
  );
}