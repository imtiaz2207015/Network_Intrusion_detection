import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../AuthContext';
import { alertsApi } from '../api';
import { formatTimestamp, formatAbsoluteTime } from '../format';

const STARTER_CHIPS = [
  'How do I spot a brute-force attack?',
  'What is a SYN flood?',
  'How do I secure SSH?',
  'What does PortScan mean?',
];

const MAX_CHARS = 500;

function renderInline(text) {
  const parts = String(text || '').split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return <strong key={idx}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return <code key={idx} className="sc-inline-code mono">{part.slice(1, -1)}</code>;
    }
    return part;
  });
}

function FormattedMessage({ content }) {
  const lines = String(content || '').split('\n');
  const blocks = [];
  let listItems = [];
  let listType = null;

  function flushList() {
    if (!listItems.length) return;
    const Tag = listType === 'ol' ? 'ol' : 'ul';
    blocks.push(
      <Tag key={`list-${blocks.length}`} className="sc-fmt-list">
        {listItems.map((item, i) => (
          <li key={i}>{renderInline(item)}</li>
        ))}
      </Tag>
    );
    listItems = [];
    listType = null;
  }

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed) {
      flushList();
      continue;
    }
    const ulMatch = trimmed.match(/^[-*•]\s+(.+)$/);
    const olMatch = trimmed.match(/^\d+[.)]\s+(.+)$/);
    if (ulMatch) {
      if (listType && listType !== 'ul') flushList();
      listType = 'ul';
      listItems.push(ulMatch[1]);
      continue;
    }
    if (olMatch) {
      if (listType && listType !== 'ol') flushList();
      listType = 'ol';
      listItems.push(olMatch[1]);
      continue;
    }
    flushList();
    blocks.push(
      <p key={`p-${blocks.length}`} className="sc-fmt-p">
        {renderInline(trimmed)}
      </p>
    );
  }
  flushList();

  return <div className="sc-fmt">{blocks}</div>;
}

export default function SecurityChat() {
  const { token } = useAuth();
  const [messages, setMessages] = useState([]);
  const [used, setUsed] = useState(0);
  const [limit, setLimit] = useState(20);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [error, setError] = useState('');
  const [copiedId, setCopiedId] = useState(null);

  async function copyReply(id, text) {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((cur) => (cur === id ? null : cur)), 1800);
    } catch {
      /* ignore */
    }
  }

  const listEndRef = useRef(null);
  const textareaRef = useRef(null);
  const tmpSeqRef = useRef(1);

  useEffect(() => {
    let alive = true;
    Promise.all([
      alertsApi('/chat/history', { token }),
      alertsApi('/chat/usage', { token }),
    ])
      .then(([hist, usage]) => {
        if (!alive) return;
        setMessages(Array.isArray(hist?.messages) ? hist.messages : []);
        setUsed(Number(usage?.used) || 0);
        setLimit(Number(usage?.limit) || 20);
      })
      .catch((e) => {
        if (alive) setError(e.message || 'Could not load chat history.');
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [token]);

  useEffect(() => {
    if (listEndRef.current && typeof listEndRef.current.scrollIntoView === 'function') {
      listEndRef.current.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }
  }, [messages, sending]);

  const atLimit = used >= limit;

  async function sendMessage(rawText) {
    const text = String(rawText ?? input).trim();
    if (!text || sending || atLimit) return;
    if (text.length > MAX_CHARS) {
      setError(`Message is too long (maximum ${MAX_CHARS} characters).`);
      return;
    }

    setError('');
    setInput('');
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }

    const tempId = `tmp-${tmpSeqRef.current++}`;
    const optimisticUser = {
      id: tempId,
      role: 'user',
      content: text,
      created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    };
    setMessages((prev) => [...prev, optimisticUser]);
    setSending(true);

    try {
      const res = await alertsApi('/chat', {
        method: 'POST',
        token,
        body: { message: text },
      });
      setMessages((prev) => {
        const withoutTmp = prev.filter((m) => m.id !== tempId);
        const savedUser = res.user_message || optimisticUser;
        const savedAssistant = res.assistant_message || {
          id: `asst-${tmpSeqRef.current++}`,
          role: 'assistant',
          content: res.reply,
          created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
        };
        return [...withoutTmp, savedUser, savedAssistant];
      });
      if (typeof res.used === 'number') setUsed(res.used);
      if (typeof res.limit === 'number') setLimit(res.limit);
    } catch (e) {
      setMessages((prev) => prev.filter((m) => m.id !== tempId));
      setInput(text);
      setError(e.message || 'Could not reach AI Chat. Please try again.');
      if (e.status === 429) {
        setUsed(limit);
      }
    } finally {
      setSending(false);
    }
  }

  async function handleClear() {
    if (clearing || sending || messages.length === 0) return;
    setClearing(true);
    setError('');
    try {
      await alertsApi('/chat/history', { method: 'DELETE', token });
      setMessages([]);
    } catch (e) {
      setError(e.message || 'Could not clear chat history.');
    } finally {
      setClearing(false);
    }
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  function handleInputChange(e) {
    const val = e.target.value;
    setInput(val);
    if (error) setError('');
    const el = e.target;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 130)}px`;
  }

  return (
    <div className="sc-page">
      <section className="card sc-shell" aria-label="AI Chat">
        {/* Header */}
        <header className="sc-head">
          <div className="sc-head-top">
            <div className="sc-head-title-wrap">
              <div className="sc-head-icon" aria-hidden="true">
                <svg
                  width="20"
                  height="20"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M12 2L4 5.5v6c0 5.3 3.4 9.9 8 11.5 4.6-1.6 8-6.2 8-11.5v-6L12 2z" />
                  <path d="M9.5 11.5h5M12 9v5" />
                </svg>
              </div>
              <div>
                <h2>AI Chat</h2>
                <p className="sc-privacy-note">
                  Recent alert summaries (including IP addresses) from your account are sent to the AI provider as context.
                </p>
              </div>
            </div>

            <div className="sc-head-actions">
              <span
                className={'badge mono sc-usage-badge' + (atLimit ? ' at-limit' : '')}
                aria-live="polite"
              >
                {used}/{limit} messages today
              </span>
              <button
                type="button"
                className="btn ghost sm sc-clear-btn"
                onClick={handleClear}
                disabled={clearing || sending || messages.length === 0}
              >
                {clearing ? 'Clearing...' : 'Clear chat'}
              </button>
            </div>
          </div>
        </header>

        {/* Scrollable Message List */}
        <div className="sc-messages" role="log" aria-live="polite" aria-label="Chat messages">
          {loading ? (
            <div className="sc-empty">
              <p className="mono" style={{ color: 'var(--muted)' }}>Loading conversation...</p>
            </div>
          ) : messages.length === 0 && !sending ? (
            <div className="sc-empty">
              <div className="sc-empty-icon" aria-hidden="true">
                <svg
                  width="28"
                  height="28"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.9"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z" />
                </svg>
              </div>
              <h3>Ask a network security question</h3>
              <p>
                Learn about PortScans, SYN floods, brute-force attacks, hardening SSH, or how to use SentinelIQ.
              </p>
              <div className="sc-starters" role="group" aria-label="Starter questions">
                {STARTER_CHIPS.map((q) => (
                  <button
                    key={q}
                    type="button"
                    className="sc-chip"
                    disabled={sending || atLimit}
                    onClick={() => sendMessage(q)}
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <>
              {messages.map((m) => {
                const isUser = m.role === 'user';
                return (
                  <div
                    key={m.id}
                    className={'sc-msg-row ' + (isUser ? 'is-user' : 'is-assistant')}
                  >
                    {!isUser && (
                      <div className="sc-bot-avatar mono" aria-hidden="true">
                        AI
                      </div>
                    )}
                    <div className={'sc-bubble ' + (isUser ? 'is-user' : 'is-assistant')}>
                      <div className="sc-bubble-text">
                        {isUser ? m.content : <FormattedMessage content={m.content} />}
                      </div>
                      <div className="sc-bubble-foot">
                        {m.created_at && (
                          <span
                            className="sc-bubble-time mono"
                            title={formatAbsoluteTime(m.created_at)}
                          >
                            {formatTimestamp(m.created_at)}
                          </span>
                        )}
                        {!isUser && (
                          <button
                            type="button"
                            className="sc-copy-btn mono"
                            onClick={() => copyReply(m.id, m.content)}
                            aria-label="Copy response"
                          >
                            {copiedId === m.id ? '✓ Copied' : 'Copy'}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}

              {sending && (
                <div className="sc-msg-row is-assistant" role="status" aria-label="AI Chat is typing">
                  <div className="sc-bot-avatar mono" aria-hidden="true">
                    AI
                  </div>
                  <div className="sc-bubble is-assistant sc-typing">
                    <span className="sc-dot" />
                    <span className="sc-dot" />
                    <span className="sc-dot" />
                  </div>
                </div>
              )}
            </>
          )}
          <div ref={listEndRef} />
        </div>

        {/* Error Banner */}
        {error && (
          <div className="sc-error-wrap">
            <div className="help-banner err" role="alert">
              <span>!</span>
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Fixed Bottom Input Bar */}
        <form
          className="sc-input-bar"
          onSubmit={(e) => {
            e.preventDefault();
            sendMessage();
          }}
        >
          <div className="sc-input-wrap">
            <textarea
              ref={textareaRef}
              className="input sc-textarea"
              rows={1}
              maxLength={MAX_CHARS}
              placeholder={
                atLimit
                  ? `Daily limit reached (${limit}/${limit} messages today)`
                  : 'Ask about recent alerts, why a flow was flagged, or network defense...'
              }
              aria-label="Message AI Chat"
              value={input}
              disabled={sending || atLimit}
              onChange={handleInputChange}
              onKeyDown={handleKeyDown}
            />
            {input.length > 380 && (
              <span className="mono sc-char-count">
                {input.length}/{MAX_CHARS}
              </span>
            )}
          </div>
          <button
            type="submit"
            className="btn sc-send-btn"
            disabled={sending || atLimit || !input.trim()}
            aria-label="Send message"
          >
            <span>Send</span>
            <svg
              width="15"
              height="15"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <line x1="22" y1="2" x2="11" y2="13" />
              <polygon points="22 2 15 22 11 13 2 9 22 2" />
            </svg>
          </button>
        </form>
      </section>
    </div>
  );
}
