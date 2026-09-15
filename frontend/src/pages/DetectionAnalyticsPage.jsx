import { useState } from 'react';
import { Panel } from '../components/Panel';
import { SeverityBadge } from '../components/SeverityBadge';
import { EmptyState } from '../components/EmptyState';
import { api, ApiError } from '../api/client';

export function DetectionAnalyticsPage() {
  const [featuresJson, setFeaturesJson] = useState('{\n  "duration": 1.0,\n  "packet_count": 10.0\n}');
  const [sourceIp, setSourceIp] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const features = JSON.parse(featuresJson);
      const payload = { features };
      if (sourceIp.trim()) payload.source_ip = sourceIp.trim();
      const res = await api.detect(payload);
      setResult(res);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  const is503 = error instanceof ApiError && error.status === 503;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Detection Analytics</h1>
        <p className="page-subtitle">Send a feature vector to <code className="mono">/detect</code> and inspect the real response.</p>
      </div>

      <div className="grid grid-cols-2">
        <Panel title="Submit a sample">
          <form onSubmit={handleSubmit}>
            <div className="field-group" style={{ marginBottom: 'var(--space-3)' }}>
              <label className="field-label" htmlFor="features">Features (JSON, feature name → value)</label>
              <textarea
                id="features"
                className="field-input"
                rows={6}
                value={featuresJson}
                onChange={(e) => setFeaturesJson(e.target.value)}
                style={{ fontFamily: 'var(--font-mono)', resize: 'vertical' }}
              />
            </div>
            <div className="field-group" style={{ marginBottom: 'var(--space-3)' }}>
              <label className="field-label" htmlFor="source_ip">Source IP (optional — required for auto-block, Phase 12)</label>
              <input
                id="source_ip"
                className="field-input"
                value={sourceIp}
                onChange={(e) => setSourceIp(e.target.value)}
                placeholder="203.0.113.55"
              />
            </div>
            <button className="btn" type="submit" disabled={loading}>
              {loading ? 'Sending…' : 'Run detection'}
            </button>
          </form>
        </Panel>

        <Panel title="Result">
          {!result && !error && (
            <EmptyState title="No detection run yet." detail="Submit a sample on the left to see a real response here." />
          )}

          {is503 && (
            <EmptyState
              tone="error"
              title="No trained detection model is loaded."
              detail={error.detail || 'This is the expected, honest state until a model is trained on real CICIDS2017 data and placed in ml/models/. See docs/methodology/preprocessing.md.'}
            />
          )}

          {error && !is503 && (
            <EmptyState tone="error" title="Request failed." detail={error.detail || error.message} />
          )}

          {result && (
            <div>
              <div style={{ marginBottom: 'var(--space-3)' }}>
                <SeverityBadge severity={result.severity} />
                {result.is_malicious && <span style={{ marginLeft: 8, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>Malicious</span>}
                {!result.is_malicious && <span style={{ marginLeft: 8, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>Benign</span>}
              </div>
              <dl className="mono" style={{ fontSize: 'var(--text-sm)', lineHeight: 1.8 }}>
                <div><strong>attack_type:</strong> {result.attack_type}</div>
                <div><strong>confidence:</strong> {result.confidence.toFixed(4)}</div>
                <div><strong>model_used:</strong> {result.model_used}</div>
                <div><strong>event_id:</strong> {result.event_id ?? 'null (benign)'}</div>
                <div><strong>auto_block_triggered:</strong> {String(result.auto_block_triggered)}</div>
              </dl>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 'var(--space-3)' }}>
                {result.severity_rationale}
              </p>
              {result.auto_block_message && (
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                  Block decision: {result.auto_block_message}
                </p>
              )}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
