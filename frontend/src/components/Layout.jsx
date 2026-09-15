import { NavLink, Outlet } from 'react-router-dom';
import { useLiveAlerts } from '../hooks/useLiveAlerts';
import { StatusPill } from './StatusPill';

const NAV_ITEMS = [
  { to: '/', label: 'Overview', end: true },
  { to: '/attacks', label: 'Live Attacks' },
  { to: '/detection', label: 'Detection Analytics' },
  { to: '/crypto', label: 'Crypto Analytics' },
  { to: '/sahe', label: 'SAHE Decisions' },
  { to: '/benchmarks', label: 'Benchmark Results' },
  { to: '/firewall', label: 'Firewall Actions' },
];

export function Layout() {
  const { connectionState } = useLiveAlerts();

  return (
    <div className="app-shell">
      <nav className="rail">
        <div className="rail-brand">
          <span className="rail-brand-mark">SAHE</span>
          <span className="rail-brand-sub">Cloud IDS/IPS</span>
        </div>

        <ul className="rail-nav">
          {NAV_ITEMS.map((item) => (
            <li key={item.to}>
              <NavLink
                to={item.to}
                end={item.end}
                className={({ isActive }) => `rail-link${isActive ? ' rail-link-active' : ''}`}
              >
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>

        <div className="rail-footer">
          <StatusPill state={connectionState === 'open' ? 'ok' : connectionState === 'connecting' ? 'pending' : 'error'}>
            {connectionState === 'open' ? 'Live feed connected' : connectionState === 'connecting' ? 'Connecting…' : 'Feed disconnected'}
          </StatusPill>
        </div>
      </nav>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
