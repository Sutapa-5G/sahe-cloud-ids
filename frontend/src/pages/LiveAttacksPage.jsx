import { Panel } from '../components/Panel';
import { SeverityBadge } from '../components/SeverityBadge';
import { EmptyState } from '../components/EmptyState';
import { useLiveAlerts } from '../hooks/useLiveAlerts';

export function LiveAttacksPage() {
  const { alerts, connectionState } = useLiveAlerts();

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Live Attacks</h1>
        <p className="page-subtitle">
          Real-time feed from <code className="mono">/ws/events</code> — connection: <span className="mono">{connectionState}</span>
        </p>
      </div>

      <Panel title={`${alerts.length} alert${alerts.length === 1 ? '' : 's'} this session`}>
        {alerts.length === 0 ? (
          <EmptyState
            title="No malicious detections broadcast yet."
            detail="Benign detections do not appear here by design — only malicious classifications raise an alert (see AlertService, Phase 11)."
          />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Event ID</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a, i) => (
                <tr key={a.event_id ?? i}>
                  <td className="mono">{a.timestamp ? new Date(a.timestamp).toLocaleString() : '—'}</td>
                  <td>{a.attack_type}</td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td className="mono">{typeof a.confidence === 'number' ? a.confidence.toFixed(4) : '—'}</td>
                  <td className="mono">{a.event_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
