import { useState } from 'react';
import metrics from '../modelMetrics.json';

const pct = (v) => (v * 100).toFixed(2) + '%';
const num = (n) => n.toLocaleString();

const SHORT_TITLES = {
  binary78: 'Binary RF (78 feat)',
  binary23: 'Live Binary (23 feat)',
  multiclass: 'Multiclass (11 classes)',
};

function Bar({ value, color }) {
  return (
    <div style={{ background: 'var(--surface-2)', borderRadius: 6, height: 8, minWidth: 60 }}>
      <div style={{ width: `${value * 100}%`, height: '100%', borderRadius: 6, background: color }} />
    </div>
  );
}

function Matrix({ model }) {
  const big = model.classes.length > 2;
  const rowLabel = (i) => (big ? `${i + 1}. ${model.classes[i]}` : model.classes[i]);
  return (
    <div className="table-scroll-wrap mp-matrix-wrap">
      <table className={'mp-matrix-table' + (big ? ' is-big' : '')} style={{ borderCollapse: 'separate', borderSpacing: 3, fontSize: big ? 11 : 14 }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'right', color: 'var(--muted)', fontWeight: 500, paddingRight: 8, whiteSpace: 'nowrap' }}>
              Actual ↓ / Pred →
            </th>
            {model.classes.map((c, j) => (
              <th key={c} style={{ color: 'var(--muted)', fontWeight: 500, padding: '0 4px', whiteSpace: 'nowrap' }}>
                {big ? j + 1 : c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {model.confusion.map((row, i) => {
            const total = row.reduce((a, b) => a + b, 0) || 1;
            return (
              <tr key={i}>
                <td style={{ textAlign: 'right', paddingRight: 8, whiteSpace: 'nowrap' }}>{rowLabel(i)}</td>
                {row.map((v, j) => {
                  const a = v / total;
                  let bg = 'var(--surface-2)';
                  if (v > 0) {
                    const pctMix = Math.round(Math.min(100, Math.max(18, (i === j ? a : a * 6) * 100)));
                    bg = i === j
                      ? `color-mix(in srgb, var(--accent) ${pctMix}%, var(--surface-2))`
                      : `color-mix(in srgb, var(--danger) ${Math.min(80, pctMix)}%, var(--surface-2))`;
                  }
                  return (
                    <td key={j} className={'mono mp-matrix-cell' + (big ? ' big' : ' binary')} style={{
                      background: bg, borderRadius: 6, textAlign: 'center',
                      fontWeight: i === j ? 700 : 400,
                      color: i === j && a > 0.6 ? 'var(--btn-text)' : 'inherit',
                    }}>{num(v)}</td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function ModelPerformance() {
  const [key, setKey] = useState('binary23');
  const model = metrics.models.find((m) => m.key === key);

  const weak = [...model.per_class]
    .filter((c) => c.support >= 50 && c.f1 < 0.95)
    .sort((a, b) => a.f1 - b.f1)
    .slice(0, 3);

  const th = { textAlign: 'left', color: 'var(--muted)', fontWeight: 500, padding: '6px 10px', fontSize: 12 };
  const td = { padding: '8px 10px', fontSize: 14 };

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <div>
        <h2>Model Performance</h2>
        <p style={{ color: 'var(--muted)', margin: '4px 0 0', fontSize: 13 }}>
          {metrics.dataset} · {metrics.split} · offline held-out test set
        </p>
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 4 }}>Model comparison</div>
        <p style={{ color: 'var(--muted)', fontSize: 12.5, marginBottom: 10 }}>
          Click or press Enter/Space on any row to inspect its metrics and confusion matrix below.
        </p>
        <div className="table-scroll-wrap mp-comp-wrap">
          <table className="table mp-comp-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th className="mp-sticky-col" style={th}>Model</th>
                <th className="mp-num-col" style={th}>Features</th>
                <th className="mp-num-col" style={th}>Test rows</th>
                <th className="mp-num-col" style={th}>Accuracy</th>
                <th className="mp-num-col" style={th}>Precision</th>
                <th className="mp-num-col" style={th}>Recall</th>
                <th className="mp-num-col" style={th}>F1</th>
              </tr>
            </thead>
            <tbody>
              {metrics.models.map((m) => {
                const selected = key === m.key;
                return (
                  <tr
                    key={m.key}
                    role="button"
                    tabIndex={0}
                    aria-selected={selected}
                    className={selected ? 'mp-row-selected' : ''}
                    onClick={() => setKey(m.key)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setKey(m.key);
                      }
                    }}
                    style={{
                      borderTop: '1px solid var(--surface-2)',
                      cursor: 'pointer',
                      background: selected ? 'var(--accent-soft)' : undefined,
                      boxShadow: selected ? 'inset 3px 0 0 var(--accent)' : undefined,
                      fontWeight: selected ? 600 : 400,
                    }}
                  >
                    <td className="mp-sticky-col" style={{ ...td, color: selected ? 'var(--accent)' : 'inherit' }}>
                      <span className="mp-title-full">{m.title}</span>
                      <span className="mp-title-short">{SHORT_TITLES[m.key] || m.title}</span>
                    </td>
                    <td className="mono mp-num-col" style={td}>{m.n_features}</td>
                    <td className="mono mp-num-col" style={td}>{num(m.test_rows)}</td>
                    <td className="mono mp-num-col" style={td}>{pct(m.accuracy)}</td>
                    <td className="mono mp-num-col" style={td}>{pct(m.precision)}</td>
                    <td className="mono mp-num-col" style={td}>{pct(m.recall)}</td>
                    <td className="mono mp-num-col" style={td}>{pct(m.f1)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <div className="stat-label" style={{ fontSize: 14, color: 'var(--text)', fontWeight: 600 }}>
          Selected model: <span style={{ color: 'var(--accent)' }}>{model.title}</span>
        </div>
        <p style={{ color: 'var(--muted)', margin: '4px 0 0', fontSize: 13 }}>{model.description}</p>
      </div>

      <div className="grid">
        <div className="card"><div className="stat-label">Accuracy</div><div className="stat-value">{pct(model.accuracy)}</div></div>
        <div className="card"><div className="stat-label">Precision</div><div className="stat-value">{pct(model.precision)}</div></div>
        <div className="card"><div className="stat-label">Recall</div><div className="stat-value">{pct(model.recall)}</div></div>
        <div className="card"><div className="stat-label">F1 score</div><div className="stat-value">{pct(model.f1)}</div></div>
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 12 }}>
          Confusion matrix (teal = correct, red = errors)
        </div>
        <Matrix model={model} />
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 12 }}>Per-class results</div>
        <div className="mp-class-list">
          {model.per_class.map((c) => (
            <div key={c.name} className="mp-class-row">
              <span className="mp-class-name">{c.name}</span>
              <div className="mp-class-bar">
                <div style={{ color: 'var(--muted)', fontSize: 11 }}>
                  Precision <span className="mono">{pct(c.precision)}</span>
                </div>
                <Bar value={c.precision} color="var(--accent)" />
              </div>
              <div className="mp-class-bar">
                <div style={{ color: 'var(--muted)', fontSize: 11 }}>
                  Recall <span className="mono">{pct(c.recall)}</span>
                </div>
                <Bar value={c.recall} color="var(--accent)" />
              </div>
              <span className="mono mp-class-f1">F1 {c.f1.toFixed(2)}</span>
              <span className="mono mp-class-sup" style={{ color: 'var(--muted)' }}>n = {num(c.support)}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 8 }}>Notes</div>
        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, color: 'var(--muted)', lineHeight: 1.7 }}>
          {model.key === 'multiclass' && (
            <li>
              Scored on attack flows only, because this model runs after the binary model flags an attack.
              Heartbleed, Infiltration and SQL Injection are not in the model (too few samples);
              {' '}{model.excluded_rows} test rows were excluded. Macro F1 over the covered classes: {pct(model.macro_f1)}.
            </li>
          )}
          {model.key === 'binary23' && (
            <li>This is the model deployed in the live sensor. It trades a little accuracy for features that can be extracted from live packets.</li>
          )}
          {weak.length > 0 && (
            <li>Weakest classes: {weak.map((c) => `${c.name} (F1 ${c.f1.toFixed(2)})`).join(', ')}.
              Web Attack Brute Force and XSS look alike at flow level in CICIDS2017.</li>
          )}
          <li>These are offline results on CICIDS2017. Live detection also uses rule-based detectors, so live behaviour differs.</li>
        </ul>
      </div>
    </div>
  );
}
