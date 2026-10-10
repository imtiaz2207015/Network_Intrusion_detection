import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import AuthShell from '../AuthShell';

export default function ResetPassword() {
  const [params] = useSearchParams();
  const token = params.get('token') || '';
  const nav = useNavigate();
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show1, setShow1] = useState(false);
  const [show2, setShow2] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError('');
    if (password !== confirm) {
      setError('Passwords do not match');
      return;
    }
    setBusy(true);
    try {
      await api('/reset-password', { method: 'POST', body: { token, password } });
      setDone(true);
      setTimeout(() => nav('/login'), 2000);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Set a new password" sub="At least 8 characters with letters and numbers.">
      <form onSubmit={submit}>
        {!token && <p className="au-err">Reset link is missing its token.</p>}
        <div className="au-pass">
          <input className="au-input" type={show1 ? 'text' : 'password'} placeholder="New password"
            value={password} autoComplete="new-password"
            onChange={(e) => setPassword(e.target.value)} />
          <button type="button" className="au-eye" onClick={() => setShow1(!show1)}>
            {show1 ? 'Hide' : 'Show'}
          </button>
        </div>
        <div className="au-pass">
          <input className="au-input" type={show2 ? 'text' : 'password'} placeholder="Confirm password"
            value={confirm} autoComplete="new-password"
            onChange={(e) => setConfirm(e.target.value)} />
          <button type="button" className="au-eye" onClick={() => setShow2(!show2)}>
            {show2 ? 'Hide' : 'Show'}
          </button>
        </div>
        {error && <p className="au-err">{error}</p>}
        {done && <p className="au-ok">Password changed. Redirecting to sign in...</p>}
        <button className="au-btn" disabled={busy || done || !token || !password || !confirm}>
          {busy ? 'Saving...' : 'Reset password'}
        </button>
      </form>
      <p className="au-foot"><Link to="/login">&larr; Back to sign in</Link></p>
    </AuthShell>
  );
}