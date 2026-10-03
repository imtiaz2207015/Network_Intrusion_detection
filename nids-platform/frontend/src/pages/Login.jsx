import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import '../auth.css';

export default function Login() {
  const { login } = useAuth();
  const nav = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await login(username, password);
      nav('/');
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="au">
      <form className="au-box" onSubmit={submit}>
        <Link to="/home" className="au-logo">NIDS<span>.</span>AI</Link>
        <h2>Welcome back</h2>
        <p className="au-sub">Sign in to your dashboard</p>
        <input className="au-input" placeholder="Username" value={username} autoFocus
          autoComplete="username" onChange={(e) => setUsername(e.target.value)} />
        <div className="au-pass">
          <input className="au-input" type={show ? 'text' : 'password'} placeholder="Password"
            value={password} autoComplete="current-password"
            onChange={(e) => setPassword(e.target.value)} />
          <button type="button" className="au-eye" onClick={() => setShow(!show)}>
            {show ? 'Hide' : 'Show'}
          </button>
        </div>
        {error && <p className="au-err" key={error}>{error}</p>}
        <button className="au-btn" disabled={busy || !username || !password}>
          {busy ? 'Signing in...' : 'Sign in'}
        </button>
        <p className="au-foot">No account? <Link to="/register">Register</Link></p>
        <p className="au-foot" style={{ marginTop: 8 }}><Link to="/home">← Back to home</Link></p>
      </form>
    </div>
  );
}