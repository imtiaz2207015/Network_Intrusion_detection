import { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { api } from '../api';
import { SENSOR_OFFLINE_GUIDE } from '../helpText';

const FAQS = [
  {
    id: 'sensor-offline',
    q: 'Sensor shows Offline',
    a: SENSOR_OFFLINE_GUIDE.subtitle,
    steps: SENSOR_OFFLINE_GUIDE.steps,
  },
  {
    id: 'no-alerts',
    q: 'No alerts are showing',
    a: 'Check that the sensor badge in the top bar shows Online and that your time-range or status filters are not hiding alerts. Make sure attacks come from another device on the network, because traffic on the same machine’s loopback is invisible.',
  },
  {
    id: 'ai-explanation',
    q: 'AI explanation does not load',
    a: 'AI explanations need an active internet connection and available API credit. Try again later if it fails—the rule-based mitigation advice on every alert still works without it.',
  },
  {
    id: 'forgot-password',
    q: 'I forgot my password',
    a: 'Use the "Forgot password" link on the login page to send a reset link to your registered email. Open the link promptly, as it expires after 15 minutes.',
  },
  {
    id: 'alert-colors',
    q: 'What do alert colors mean?',
    a: 'Critical (red) means an active attack like a DoS or SYN flood that could disrupt your network right away. High (orange) means serious activity such as brute-force password guessing or heavy UDP/ICMP packet bursts. Medium (amber/yellow) marks early probing like a port scan or unusual behavior, and Low (slate/muted) covers informational or benign events.',
  },
];

export default function Help() {
  const { token } = useAuth();
  const { hash } = useLocation();
  const reportRef = useRef(null);

  const [openIdx, setOpenIdx] = useState(0);

  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [context, setContext] = useState('');
  const [touched, setTouched] = useState({ subject: false, message: false, context: false });
  const [sending, setSending] = useState(false);
  const [okMsg, setOkMsg] = useState('');
  const [errMsg, setErrMsg] = useState('');

  useEffect(() => {
    if (hash === '#report' && reportRef.current) {
      reportRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    if (hash) {
      const targetId = hash.slice(1);
      const faqIdx = FAQS.findIndex((item) => item.id === targetId);
      if (faqIdx !== -1) {
        setOpenIdx(faqIdx);
        const el = document.getElementById(targetId);
        if (el) {
          el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }
    }
  }, [hash]);

  const cleanSubject = subject.replace(/\s+/g, ' ').trim();
  const cleanMessage = message.trim();
  const cleanContext = context.replace(/\s+/g, ' ').trim();

  const subjectErr =
    cleanSubject.length < 3 || cleanSubject.length > 100
      ? 'Subject must be 3–100 characters.'
      : '';
  const messageErr =
    cleanMessage.length < 10 || cleanMessage.length > 1000
      ? 'Message must be 10–1000 characters.'
      : '';
  const contextErr =
    cleanContext.length > 200
      ? 'Related alert or IP must be at most 200 characters.'
      : '';

  async function onSubmit(e) {
    e.preventDefault();
    setTouched({ subject: true, message: true, context: true });
    setOkMsg('');
    setErrMsg('');

    if (subjectErr || messageErr || contextErr) return;

    setSending(true);
    try {
      await api('/report', {
        method: 'POST',
        token,
        body: {
          subject: cleanSubject,
          message: cleanMessage,
          context: cleanContext,
        },
      });
      setOkMsg('Sent. We will reply to your account email.');
      setSubject('');
      setMessage('');
      setContext('');
      setTouched({ subject: false, message: false, context: false });
    } catch (err) {
      setErrMsg(err.message || 'Could not send report. Please try again.');
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="st help-page">
      <div style={{ marginBottom: 16 }}>
        <h2>Help &amp; Support</h2>
        <p className="band-sub">
          Quick answers to common setup and alert questions, or send a message directly to support.
        </p>
      </div>

      <div className="st-cols">
        {/* 1) FAQ Accordion Card */}
        <section className="card" aria-labelledby="faq-heading">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
            <div>
              <div id="faq-heading" className="stat-label" style={{ marginBottom: 4 }}>
                Frequently Asked Questions
              </div>
              <p className="band-sub">Click or press Enter/Space on any question to view the solution.</p>
            </div>
            <span className="badge mono">{FAQS.length} topics</span>
          </div>

          <div className="faq-list">
            {FAQS.map((item, idx) => {
              const isOpen = openIdx === idx;
              const btnId = `faq-btn-${idx}`;
              const panelId = `faq-panel-${idx}`;
              return (
                <div
                  key={item.q}
                  id={item.id}
                  style={{ scrollMarginTop: 80 }}
                  className={'faq-item' + (isOpen ? ' open' : '')}
                >
                  <button
                    id={btnId}
                    type="button"
                    className="faq-trigger"
                    aria-expanded={isOpen}
                    aria-controls={panelId}
                    onClick={() => setOpenIdx(isOpen ? -1 : idx)}
                  >
                    <span className="faq-q">{item.q}</span>
                    <span className={'faq-chev' + (isOpen ? ' open' : '')} aria-hidden="true">
                      ▾
                    </span>
                  </button>
                  <div
                    id={panelId}
                    role="region"
                    aria-labelledby={btnId}
                    hidden={!isOpen}
                    className="faq-panel"
                  >
                    <p>{item.a}</p>
                    {item.steps && (
                      <div className="dash-sensor-steps" style={{ marginTop: 10 }}>
                        {item.steps.map((step) => (
                          <div key={step.num} className="dash-sensor-step">
                            <span className="dash-step-num mono">{step.num}</span>
                            <div>
                              <b>{step.title}</b>
                              <p>{step.text}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* 2) Report a Problem Card */}
        <section id="report" ref={reportRef} className="card help-report-card" aria-labelledby="report-heading">
          <div style={{ marginBottom: 14 }}>
            <div id="report-heading" className="stat-label" style={{ marginBottom: 4 }}>
              Report a problem
            </div>
            <p className="band-sub">
              Need more help? Describe what happened below and our team will reply to your account email.
            </p>
          </div>

          <form onSubmit={onSubmit} noValidate className="help-form">
            <div className="help-field">
              <div className="help-label-row">
                <label htmlFor="report-subject">Subject</label>
                <span className="mono help-counter">{subject.length}/100</span>
              </div>
              <input
                id="report-subject"
                className="input"
                type="text"
                maxLength={100}
                placeholder="e.g. Sensor stays offline after reboot"
                value={subject}
                disabled={sending}
                onChange={(e) => {
                  setSubject(e.target.value);
                  if (okMsg) setOkMsg('');
                }}
                onBlur={() => setTouched((t) => ({ ...t, subject: true }))}
                aria-invalid={touched.subject && !!subjectErr}
              />
              {touched.subject && subjectErr && (
                <small className="help-inline-err" role="alert">{subjectErr}</small>
              )}
            </div>

            <div className="help-field">
              <div className="help-label-row">
                <label htmlFor="report-message">Message</label>
                <span className={'mono help-counter' + (message.length > 1000 ? ' over' : '')}>
                  {message.length}/1000
                </span>
              </div>
              <textarea
                id="report-message"
                className="input help-textarea"
                rows={5}
                maxLength={1000}
                placeholder="Tell us what you saw, which page you were on, and any steps you tried (10–1000 characters)..."
                value={message}
                disabled={sending}
                onChange={(e) => {
                  setMessage(e.target.value);
                  if (okMsg) setOkMsg('');
                }}
                onBlur={() => setTouched((t) => ({ ...t, message: true }))}
                aria-invalid={touched.message && !!messageErr}
              />
              {touched.message && messageErr && (
                <small className="help-inline-err" role="alert">{messageErr}</small>
              )}
            </div>

            <div className="help-field">
              <div className="help-label-row">
                <label htmlFor="report-context">
                  Related alert or IP <span style={{ color: 'var(--muted)', fontWeight: 400 }}>(optional)</span>
                </label>
                <span className="mono help-counter">{context.length}/200</span>
              </div>
              <input
                id="report-context"
                className="input mono"
                type="text"
                maxLength={200}
                placeholder="e.g. Alert #42 or 10.129.51.85"
                value={context}
                disabled={sending}
                onChange={(e) => {
                  setContext(e.target.value);
                  if (okMsg) setOkMsg('');
                }}
                onBlur={() => setTouched((t) => ({ ...t, context: true }))}
                aria-invalid={touched.context && !!contextErr}
              />
              {touched.context && contextErr && (
                <small className="help-inline-err" role="alert">{contextErr}</small>
              )}
            </div>

            {okMsg && (
              <div className="help-banner ok" role="status">
                <span>✓</span>
                <span>{okMsg}</span>
              </div>
            )}

            {errMsg && (
              <div className="help-banner err" role="alert">
                <span>!</span>
                <span>{errMsg}</span>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 4 }}>
              <button type="submit" className="btn help-submit-btn" disabled={sending}>
                {sending && <span className="help-spinner" aria-hidden="true" />}
                <span>{sending ? 'Sending...' : 'Send report'}</span>
              </button>
            </div>
          </form>
        </section>
      </div>
    </div>
  );
}

