/**
 * Used throughout the dashboard to label whether data shown is REAL
 * (backend-served, live) or a placeholder/unavailable state — per this
 * project's discipline against fabricating results, the UI must never
 * silently show empty/zero data as if it were a real measurement.
 */
export function StatusPill({ state, children }) {
  return <span className={`status-pill status-${state}`}>{children}</span>;
}
