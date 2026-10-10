import { usePolling } from './utils';

export default function SensorBadge() {
  const { data } = usePolling('/sensor', 5000);
  const online = !!(data && data.online);
  const color = online ? '#22c55e' : 'var(--danger)';
  const label = !data ? 'Sensor...' : online ? 'Sensor online'
    : data.seen ? 'Sensor offline' : 'No sensor yet';
  const tip = data && data.seen
    ? `${data.host} - last seen ${data.age}s ago - ${data.packets} packets`
    : 'No heartbeat received yet';

  return (
    <span title={tip} style={{
      display: 'inline-flex', alignItems: 'center', gap: 6, padding: '6px 12px',
      borderRadius: 999, fontSize: 13, fontWeight: 600,
      border: '1px solid rgba(255,255,255,.12)', background: 'var(--surface-2)' }}>
      <span style={{
        width: 8, height: 8, borderRadius: '50%',
        background: data ? color : 'var(--muted)',
        boxShadow: online ? `0 0 8px ${color}` : 'none' }} />
      {label}
    </span>
  );
}