import { useEffect, useState } from 'react';
import { Panel } from '../components/Panel';
import { SeverityBadge } from '../components/SeverityBadge';
import { EmptyState } from '../components/EmptyState';
import { useLiveAlerts } from '../hooks/useLiveAlerts';
import { api, ApiError } from '../api/client';

export function OverviewPage() {
  const { alerts, connectionState } = useLiveAlerts();
  const [events, setEvents] = useState(null);
  const [eventsError, setEventsError] = useState(null);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
    api.listEvents().then(setEvents).catch((err) => setEventsError(err));
  }, []);

  const severityCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const a of alerts) {
    if (a.severity in severityCounts) severityCounts[a.severity] += 1;
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Overview</h1>
        <p className="page-subtitle">
          Backend: {health ? <span className="mono">reachable</span> : <span className="mono">unreachable</span>}
          {' · '}
          Live feed: <span className="mono">{connectionState}</span>
        </p>
      </div>

      <div className="grid grid-cols-4" style={{ marginBottom: 'var(--space-5)' }}>
        <Panel className="stat-tile">
          <div className="stat-tile-value">{alerts.length}</div>
          <div className="stat-tile-label">Alerts this session</div>
        </Panel>
        <Panel className="stat-tile">
          <div className="stat-tile-value" style={{ color: 'var(--severity-critical)' }}>
            {severityCounts.CRITICAL + severityCounts.HIGH}
          </div>
          <div className="stat-tile-label">High + critical</div>
        </Panel>
        <Panel className="stat-tile">
          <div className="stat-tile-value">{events ? events.length : '—'}</div>
          <div className="stat-tile-label">Stored events</div>
        </Panel>
        <Panel className="stat-tile">
          <div className="stat-tile-value">{alerts.filter((a) => a.type === 'alert').length ? alerts[0]?.attack_type ?? '—' : '—'}</div>
          <div className="stat-tile-label">Most recent attack type</div>
        </Panel>
      </div>

      <Panel title="Recent Alerts" subtitle="Live, session-only — from the WebSocket feed">
        {alerts.length === 0 ? (
          <EmptyState
            title="No alerts received yet this session."
            detail="This is real — the dashboard has not fabricated any alert data. Alerts appear here the moment a malicious detection is broadcast by the backend."
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
              {alerts.slice(0, 10).map((a, i) => (
                <tr key={a.event_id ?? i}>
                  <td className="mono">{a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '—'}</td>
                  <td>{a.attack_type}</td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td className="mono">{typeof a.confidence === 'number' ? a.confidence.toFixed(3) : '—'}</td>
                  <td className="mono">{a.event_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {eventsError && (
        <Panel title="Stored Events">
          <EmptyState
            tone="error"
            title="Could not load stored events."
            detail={eventsError instanceof ApiError ? eventsError.detail || eventsError.message : String(eventsError)}
          />
        </Panel>
      )}
    </div>
  );
}
