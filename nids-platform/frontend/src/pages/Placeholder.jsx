export default function Placeholder({ title, note }) {
  return (
    <div className="card" style={{ maxWidth: 640 }}>
      <h2>{title}</h2>
      <p style={{ color: 'var(--muted)', marginTop: 8 }}>{note}</p>
    </div>
  );
}
