import { usePolling } from './utils';
import { humanAge } from './format';

export default function SensorBadge({ showFull = false }) {
  const { data } = usePolling('/sensor', 5000);
  const online = !!(data && data.online);
  const color = online ? 'var(--ok)' : 'var(--danger)';
  const ageText = data && data.seen ? humanAge(data.age) : '';

  const label = !data
    ? 'Sensor...'
    : online
      ? 'Sensor online'
      : data.seen
        ? `Sensor offline · ${ageText}`
        : 'No sensor yet';

  const shortLabel = !data ? 'Sensor...' : online ? 'Online' : 'Offline';

  const tip = data && data.seen
    ? `${data.host || 'sensor'} · last seen ${ageText} · ${(data.packets || 0).toLocaleString()} packets`
    : 'No heartbeat received yet';

  return (
    <span title={tip} className={'sensor-pill' + (showFull ? ' sensor-pill-full' : '')}>
      <span
        className={'sensor-dot' + (online ? ' online' : '')}
        style={{ background: data ? color : 'var(--muted)' }}
      />
      <span className="sensor-label-full">{label}</span>
      {!showFull && <span className="sensor-label-short">{shortLabel}</span>}
      {online && ageText && (
        <small className="mono sensor-age">{ageText}</small>
      )}
    </span>
  );
}
