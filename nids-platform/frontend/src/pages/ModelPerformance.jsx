import { useState } from 'react';
import metrics from '../modelMetrics.json';

const pct = (v) => (v * 100).toFixed(2) + '%';
const num = (n) => n.toLocaleString();

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
    <div style={{ overflowX: 'auto' }}>
      <table style={{ borderCollapse: 'separate', borderSpacing: 3, fontSize: big ? 11 : 14 }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'right', color: 'var(--muted)', fontWeight: 500, paddingRight: 8 }}>
              Actual ↓ &nbsp;/&nbsp; Predicted →
            </th>
            {model.classes.map((c, j) => (
              <th key={c} style={{ color: 'var(--muted)', fontWeight: 500, padding: '0 4px' }}>
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
                    bg = i === j
                      ? `rgba(34,211,238,${Math.max(0.15, a)})`
                      : `rgba(248,113,113,${Math.min(0.75, Math.max(0.2, a * 6))})`;
                  }
                  return (
                    <td key={j} style={{
                      background: bg, borderRadius: 6, textAlign: 'center',
                      padding: big ? '6px 8px' : '20px 34px',
                      fontWeight: i === j ? 700 : 400,
                      color: i === j && a > 0.6 ? '#06101f' : 'inherit',
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

      <div className="card" style={{ overflowX: 'auto' }}>
        <div className="stat-label" style={{ marginBottom: 8 }}>Model comparison</div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={th}>Model</th><th style={th}>Features</th><th style={th}>Test rows</th>
              <th style={th}>Accuracy</th><th style={th}>Precision</th><th style={th}>Recall</th><th style={th}>F1</th>
            </tr>
          </thead>
          <tbody>
            {metrics.models.map((m) => (
              <tr key={m.key} style={{ borderTop: '1px solid var(--surface-2)' }}>
                <td style={td}>{m.title}</td>
                <td style={td}>{m.n_features}</td>
                <td style={td}>{num(m.test_rows)}</td>
                <td style={td}>{pct(m.accuracy)}</td>
                <td style={td}>{pct(m.precision)}</td>
                <td style={td}>{pct(m.recall)}</td>
                <td style={td}>{pct(m.f1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {metrics.models.map((m) => (
          <button key={m.key} onClick={() => setKey(m.key)}
            style={{
              padding: '9px 16px', borderRadius: 8, cursor: 'pointer', fontWeight: 600,
              border: '1px solid var(--surface-2)',
              color: key === m.key ? '#06101f' : 'inherit',
              background: key === m.key
                ? 'linear-gradient(90deg, var(--accent), var(--accent-2))'
                : 'var(--surface-2)',
            }}>{m.title}</button>
        ))}
      </div>

      <p style={{ color: 'var(--muted)', margin: 0, fontSize: 13 }}>{model.description}</p>

      <div className="grid">
        <div className="card"><div className="stat-label">Accuracy</div><div className="stat-value">{pct(model.accuracy)}</div></div>
        <div className="card"><div className="stat-label">Precision</div><div className="stat-value">{pct(model.precision)}</div></div>
        <div className="card"><div className="stat-label">Recall</div><div className="stat-value">{pct(model.recall)}</div></div>
        <div className="card"><div className="stat-label">F1 score</div><div className="stat-value">{pct(model.f1)}</div></div>
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 12 }}>
          Confusion matrix (cyan = correct, red = errors)
        </div>
        <Matrix model={model} />
      </div>

      <div className="card">
        <div className="stat-label" style={{ marginBottom: 12 }}>Per-class results</div>
        <div style={{ overflowX: 'auto' }}>
          <div style={{ minWidth: 520 }}>
            {model.per_class.map((c) => (
              <div key={c.name} style={{
                display: 'grid', gridTemplateColumns: '1.6fr 1fr 1fr 70px 80px',
                gap: 12, alignItems: 'center', marginBottom: 10, fontSize: 13,
              }}>
                <span>{c.name}</span>
                <div><div style={{ color: 'var(--muted)', fontSize: 11 }}>Precision {pct(c.precision)}</div>
                  <Bar value={c.precision} color="var(--accent)" /></div>
                <div><div style={{ color: 'var(--muted)', fontSize: 11 }}>Recall {pct(c.recall)}</div>
                  <Bar value={c.recall} color="var(--accent-2)" /></div>
                <span>F1 {c.f1.toFixed(2)}</span>
                <span style={{ color: 'var(--muted)' }}>n = {num(c.support)}</span>
              </div>
            ))}
          </div>
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