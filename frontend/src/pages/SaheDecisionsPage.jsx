import { useEffect, useState } from 'react';
import { Panel } from '../components/Panel';
import { EmptyState } from '../components/EmptyState';
import { api } from '../api/client';

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const DATA_TYPES = ['LOG', 'ALERT', 'FILE', 'AUDIT'];
const SIZE_PRESETS = [
  { label: '1 KB', bytes: 1024 },
  { label: '100 KB', bytes: 100 * 1024 },
  { label: '1 MB', bytes: 1024 * 1024 },
  { label: '10 MB', bytes: 10 * 1024 * 1024 },
  { label: '100 MB', bytes: 100 * 1024 * 1024 },
];

export function SaheDecisionsPage() {
  const [sizeBytes, setSizeBytes] = useState(SIZE_PRESETS[1].bytes);
  const [severity, setSeverity] = useState('LOW');
  const [dataType, setDataType] = useState('LOG');
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.cryptoPolicyPreview({ payload_size_bytes: sizeBytes, severity, data_type: dataType })
      .then((res) => { setPreview(res); setError(null); })
      .catch((err) => { setError(err); setPreview(null); });
  }, [sizeBytes, severity, dataType]);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">SAHE Decisions</h1>
        <p className="page-subtitle">
          Live preview of the real policy engine (<code className="mono">crypto/sahe/policy.py</code>) via{' '}
          <code className="mono">/crypto/policy</code> — no encryption is performed, this only shows what SAHE would decide.
        </p>
      </div>

      <div className="grid grid-cols-2">
        <Panel title="Inputs">
          <div className="field-group" style={{ marginBottom: 'var(--space-4)' }}>
            <label className="field-label">Payload size</label>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {SIZE_PRESETS.map((p) => (
                <button
                  key={p.bytes}
                  type="button"
                  className={`btn ${sizeBytes === p.bytes ? '' : 'btn-secondary'}`}
                  onClick={() => setSizeBytes(p.bytes)}
                >
                  {p.label}
                </button>
              ))}
            </div>
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
        </Panel>

        <Panel title="Decision">
          {error && <EmptyState tone="error" title="Could not reach policy endpoint." detail={error.detail || error.message} />}
          {preview && (
            <div>
              <dl className="mono" style={{ fontSize: 'var(--text-sm)', lineHeight: 1.9 }}>
                <div><strong>key_establishment_method:</strong> {preview.key_establishment_method}</div>
                <div><strong>requires_signature:</strong> {String(preview.requires_signature)}</div>
              </dl>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 'var(--space-3)' }}>
                {preview.rationale}
              </p>
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Policy notes" subtitle="From docs/methodology/threshold_derivation.md">
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          The size threshold above defaults to ECDH/X25519 for smaller payloads (favoring forward secrecy)
          and RSA-OAEP for larger ones (favoring PKI compatibility at scale) — as a <em>security and
          operational</em> policy choice, not a performance-optimal one. Real benchmark data (Phase 7)
          found RSA-OAEP was actually cheaper per-message than ECDH at every tested size on the
          development hardware, which is why the threshold is no longer justified by speed. See the
          linked doc for the full analysis.
        </p>
      </Panel>
    </div>
  );
}
