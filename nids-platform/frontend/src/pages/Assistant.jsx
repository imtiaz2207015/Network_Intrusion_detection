import { useEffect, useState } from 'react';
import { alertsApi } from '../api';
import { useAuth } from '../AuthContext';
import '../assistant.css';

function sevOf(type = '') {
  const t = type.toLowerCase();
  if (t.includes('dos') || t.includes('syn')) return 'Critical';
  if (t.includes('brute') || t.includes('udp') || t.includes('icmp')) return 'High';
  return 'Medium';
}

export default function Assistant() {
  const { token, user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [sel, setSel] = useState(null);
  const [res, setRes] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const canRefresh = user?.role === 'admin' || user?.role === 'analyst';

  useEffect(() => {
    let alive = true;
    alertsApi('/?limit=30', { token })
      .then((d) => {
        if (!alive) return;
        setAlerts(d.alerts);
        setSel(d.alerts[0] || null);
      })
      .catch((e) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [token]);

  function pick(a) {
    setSel(a);
    setRes(null);
    setError('');
  }

  async function explain(refresh) {
    if (!sel) return;
    setBusy(true);
    setError('');
    try {
      setRes(await alertsApi(`/${sel.id}/explain${refresh ? '?refresh=1' : ''}`, { token }));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const sev = sel ? sevOf(sel.type) : '';
  const port = sel && sel.dport && sel.dport !== '-' ? ':' + sel.dport : '';

  return (
    <div className="as">
      <div className="as-head">
        <h1>AI Assistant</h1>
        <p>Pick an alert to get a plain-English explanation and what to do about it.</p>
      </div>

      {loading && <p className="as-note">Loading alerts...</p>}
      {!loading && alerts.length === 0 && (
        <p className="as-note">No alerts yet. Alerts from the sensor will show up here.</p>
      )}
      {error && <p className="as-error">{error}</p>}

      {alerts.length > 0 && (
        <div className="as-grid">
          <aside className="as-list">
            {alerts.map((a) => (
              <button key={a.id} className={'as-item' + (sel && sel.id === a.id ? ' on' : '')}
                onClick={() => pick(a)}>
                <i className={'as-dot as-' + sevOf(a.type).toLowerCase()} />
                <span>
                  <b>{a.type}</b>
                  <small>{a.src} | {a.time}</small>
                </span>
              </button>
            ))}
          </aside>

          {sel && (
            <section className="as-panel">
              <div className="as-top">
                <span className={'as-badge as-' + sev.toLowerCase()}>{sev}</span>
                <h2>{sel.type}</h2>
              </div>
              <p className="as-ctx">{sel.src} -&gt; {sel.dst || '-'}{port} | {sel.time}</p>
              {sel.detail && <p className="as-detail">{sel.detail}</p>}

              <div className="as-actions">
                <button className="as-btn" onClick={() => explain(false)} disabled={busy}>
                  {busy ? 'Thinking...' : 'Explain this alert'}
                </button>
                {canRefresh && res && res.ai_enabled && (
                  <button className="as-btn ghost" onClick={() => explain(true)} disabled={busy}>
                    Ask Claude again
                  </button>
                )}
              </div>

              {res && (
                <div className="as-res">
                  <div className="as-src">
                    {res.source === 'claude' ? 'Explained by Claude' : 'Built-in guide'}
                    {res.cached ? ' (saved)' : ''}
                  </div>
                  {res.note && <p className="as-note">{res.note}</p>}
                  <h3>What happened</h3>
                  <p>{res.what}</p>
                  <h3>How serious</h3>
                  <p>{res.risk}</p>
                  <h3>What to do</h3>
                  <ol>
                    {res.steps.map((s, i) => <li key={i}>{s}</li>)}
                  </ol>
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </div>
  );
}