const SEVERITY_CLASS = {
  LOW: 'severity-low',
  MEDIUM: 'severity-medium',
  HIGH: 'severity-high',
  CRITICAL: 'severity-critical',
};

export function SeverityBadge({ severity }) {
  const cls = SEVERITY_CLASS[severity] || 'severity-low';
  return <span className={`severity-badge ${cls}`}>{severity}</span>;
}
