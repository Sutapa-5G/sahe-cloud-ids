import { useEffect, useState } from 'react';
import { Panel } from '../components/Panel';
import { EmptyState } from '../components/EmptyState';
import { api, ApiError } from '../api/client';

export function FirewallActionsPage() {
  const [token, setToken] = useState('');
  const [rules, setRules] = useState(null);
  const [error, setError] = useState(null);
  const [blockIp, setBlockIp] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [actionError, setActionError] = useState(null);

  async function loadRules() {
    try {
      const res = await api.listFirewallRules();
      setRules(res);
      setError(null);
    } catch (err) {
      setError(err);
    }
  }

  useEffect(() => { loadRules(); }, []);

  async function handleBlock(e) {
    e.preventDefault();
    setActionError(null);
    try {
      await api.blockIp(blockIp, blockReason || 'manual block via dashboard', token);
      setBlockIp('');
      setBlockReason('');
      await loadRules();
    } catch (err) {
      setActionError(err);
    }
  }

  async function handleUnblock(ip) {
    setActionError(null);
    try {
      await api.unblockIp(ip, token);
      await loadRules();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Firewall Actions</h1>
        <p className="page-subtitle">
          Real state from <code className="mono">/firewall/rules</code>. Defaults to simulated mode —
          no real firewall is modified unless the backend is explicitly configured with FIREWALL_MODE=iptables.
        </p>
      </div>

      <div className="grid grid-cols-2">
        <Panel title="Manual block">
          <form onSubmit={handleBlock}>
            <div className="field-group" style={{ marginBottom: 'var(--space-3)' }}>
              <label className="field-label" htmlFor="token">API auth token</label>
              <input id="token" className="field-input" type="password" value={token} onChange={(e) => setToken(e.target.value)} />
            </div>
            <div className="field-group" style={{ marginBottom: 'var(--space-3)' }}>
              <label className="field-label" htmlFor="ip">IP address</label>
              <input id="ip" className="field-input" value={blockIp} onChange={(e) => setBlockIp(e.target.value)} placeholder="203.0.113.55" required />
            </div>
            <div className="field-group" style={{ marginBottom: 'var(--space-3)' }}>
              <label className="field-label" htmlFor="reason">Reason</label>
              <input id="reason" className="field-input" value={blockReason} onChange={(e) => setBlockReason(e.target.value)} placeholder="manual review" />
            </div>
            <button className="btn btn-danger" type="submit">Block IP</button>
            {actionError && (
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--severity-high)', marginTop: 'var(--space-2)' }}>
                {actionError instanceof ApiError ? actionError.detail || actionError.message : String(actionError)}
              </p>
            )}
          </form>
        </Panel>

        <Panel title="Active rules" subtitle={rules ? `${rules.length} rule${rules.length === 1 ? '' : 's'}` : undefined}>
          {error && <EmptyState tone="error" title="Could not load firewall rules." detail={error.message} />}
          {rules && rules.length === 0 && (
            <EmptyState title="No IPs currently blocked." detail="This reflects the real, current firewall state." />
          )}
          {rules && rules.length > 0 && (
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Mode</th>
                  <th>Reason</th>
                  <th>Blocked at</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.ip}>
                    <td className="mono">{r.ip}</td>
                    <td>{r.mode}</td>
                    <td>{r.reason}</td>
                    <td className="mono">{new Date(r.timestamp).toLocaleString()}</td>
                    <td><button className="btn btn-secondary" onClick={() => handleUnblock(r.ip)}>Unblock</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </div>
  );
}
