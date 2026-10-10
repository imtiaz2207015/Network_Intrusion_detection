import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import AuthShell from '../AuthShell';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError('');
    setMsg('');
    setBusy(true);
    try {
      const data = await api('/forgot-password', { method: 'POST', body: { email } });
      setMsg(data.message || 'If that email is registered, a reset link has been sent.');
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Forgot password?" sub="Enter your email and we will send you a reset link.">
      <form onSubmit={submit}>
        <input className="au-input" type="email" placeholder="Email" value={email}
          autoComplete="email" onChange={(e) => setEmail(e.target.value)} />
        {error && <p className="au-err">{error}</p>}
        {msg && <p className="au-ok">{msg}</p>}
        <button className="au-btn" disabled={busy || !email}>
          {busy ? 'Sending...' : 'Send reset link'}
        </button>
      </form>
      <p className="au-foot"><Link to="/login">&larr; Back to sign in</Link></p>
    </AuthShell>
  );
}