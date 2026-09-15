import { useState } from 'react';
import { Panel } from '../components/Panel';
import { EmptyState } from '../components/EmptyState';
import { api, ApiError } from '../api/client';

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const DATA_TYPES = ['LOG', 'ALERT', 'FILE', 'AUDIT'];

export function CryptoAnalyticsPage() {
  const [token, setToken] = useState('');
  const [plaintext, setPlaintext] = useState('example log line');
  const [severity, setSeverity] = useState('HIGH');
  const [dataType, setDataType] = useState('ALERT');
  const [envelope, setEnvelope] = useState(null);
  const [decrypted, setDecrypted] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleEncrypt(e) {
    e.preventDefault();
    setError(null);
    setEnvelope(null);
    setDecrypted(null);
    setLoading(true);
    try {
      const plaintext_base64 = btoa(plaintext);
      const res = await api.encrypt({ plaintext_base64, severity, data_type: dataType }, token);
      setEnvelope(res);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  async function handleDecrypt() {
    if (!envelope) return;
    setError(null);
    setLoading(true);
    try {
      const res = await api.decrypt(envelope.envelope_id, token);
      setDecrypted(atob(res.plaintext_base64));
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  const is401 = error instanceof ApiError && error.status === 401;
  const is503 = error instanceof ApiError && error.status === 503;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Crypto Analytics</h1>
        <p className="page-subtitle">
          Exercises the real SAHE engine through <code className="mono">/encrypt</code> and{' '}
          <code className="mono">/decrypt</code>. Requires the API auth token configured on the backend.
        </p>
      </div>

      <div className="grid grid-cols-2">
        <Panel title="Encrypt a payload">
          <form onSubmit={handleEncrypt}>
            <div className="field-group" style={{ marginBottom: 'var(--space-3)' }}>
              <label className="field-label" htmlFor="token">API auth token</label>
              <input id="token" className="field-input" type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="Bearer token" />
            </div>
            <div className="field-group" style={{ marginBottom: 'var(--space-3)' }}>
              <label className="field-label" htmlFor="plaintext">Plaintext</label>
              <textarea id="plaintext" className="field-input" rows={3} value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />
            </div>
            <div className="field-row">
              <div className="field-group">
                <label className="field-label" htmlFor="severity">Severity</label>
                <select id="severity" className="field-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                  {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="data_type">Data type</label>
                <select id="data_type" className="field-select" value={dataType} onChange={(e) => setDataType(e.target.value)}>
                  {DATA_TYPES.map((d) => <option key={d} value={d}>{d}</option>)}
                </select>
              </div>
            </div>
            {severity === 'CRITICAL' && dataType === 'AUDIT' && (
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--severity-high)', marginBottom: 'var(--space-3)' }}>
                AUDIT + CRITICAL triggers an Ed25519 signature (see docs/methodology/crypto_design.md).
              </p>
            )}
            <button className="btn" type="submit" disabled={loading}>{loading ? 'Encrypting…' : 'Encrypt'}</button>
          </form>
        </Panel>

        <Panel title="Result">
          {!envelope && !error && (
            <EmptyState title="No envelope yet." detail="Encrypt a payload on the left." />
          )}
          {is401 && (
            <EmptyState tone="error" title="Unauthorized." detail="Check the API auth token matches the backend's configured API_AUTH_TOKEN." />
          )}
          {is503 && (
            <EmptyState tone="error" title="Auth is not configured on this backend." detail={error.detail} />
          )}
          {error && !is401 && !is503 && (
            <EmptyState tone="error" title="Request failed." detail={error.detail || error.message} />
          )}
          {envelope && (
            <div>
              <dl className="mono" style={{ fontSize: 'var(--text-sm)', lineHeight: 1.8, wordBreak: 'break-all' }}>
                <div><strong>envelope_id:</strong> {envelope.envelope_id}</div>
                <div><strong>key_establishment_method:</strong> {envelope.key_establishment_method}</div>
                <div><strong>requires_signature:</strong> {String(envelope.requires_signature)}</div>
                <div><strong>ciphertext (base64):</strong> {envelope.ciphertext_base64.slice(0, 40)}…</div>
              </dl>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', margin: 'var(--space-3) 0' }}>
                {envelope.rationale}
              </p>
              <button className="btn btn-secondary" onClick={handleDecrypt} disabled={loading}>
                {loading ? 'Decrypting…' : 'Decrypt this envelope'}
              </button>
              {decrypted !== null && (
                <p style={{ marginTop: 'var(--space-3)' }}>
                  <strong>Decrypted:</strong> <span className="mono">{decrypted}</span>
                </p>
              )}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
