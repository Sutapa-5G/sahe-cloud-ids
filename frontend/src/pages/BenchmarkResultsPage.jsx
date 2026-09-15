import { useEffect, useState } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';
import { Panel } from '../components/Panel';
import { EmptyState } from '../components/EmptyState';
import { api } from '../api/client';

const ALGO_COLORS = {
  'AES-256-GCM': '#5B8DEF',
  'ECDH-X25519-Hybrid': '#4A9B7F',
  'RSA-OAEP-Hybrid': '#C9A227',
  DES: '#8A93A3',
  '3DES': '#D2691E',
  Blowfish: '#C4453D',
};

export function BenchmarkResultsPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.getAllBenchmarks().then(setData).catch(setError);
  }, []);

  if (error) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Benchmark Results</h1>
        </div>
        <Panel>
          <EmptyState
            tone="error"
            title="No benchmark data available from the backend."
            detail={
              error.status === 503
                ? 'Run "python -m crypto.benchmarks.run_suite" (Phase 7) to generate experiments/results/crypto_benchmark_aggregated.json, then restart the backend.'
                : error.detail || error.message
            }
          />
        </Panel>
      </div>
    );
  }

  if (!data) {
    return (
      <div>
        <div className="page-header"><h1 className="page-title">Benchmark Results</h1></div>
        <Panel><EmptyState title="Loading…" /></Panel>
      </div>
    );
  }

  // Reshape the real aggregated results into per-algorithm series for
  // the chart: one row per payload_size_bytes, one column per algorithm.
  const bySize = {};
  for (const entry of data.results) {
    const key = entry.payload_size_bytes;
    if (!bySize[key]) bySize[key] = { size: key };
    bySize[key][entry.algorithm] = entry.total_operation_seconds?.mean != null
      ? entry.total_operation_seconds.mean * 1000
      : null;
  }
  const chartData = Object.values(bySize).sort((a, b) => a.size - b.size);
  const algorithms = [...new Set(data.results.map((r) => r.algorithm))];

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Benchmark Results</h1>
        <p className="page-subtitle">
          Real measurements from Phase 7 (<code className="mono">experiments/results/crypto_benchmark_aggregated.json</code>).
          {data.metadata?.repetitions && ` ${data.metadata.repetitions} repetitions per data point.`}
        </p>
      </div>

      <Panel title="Total operation time vs. payload size" subtitle="Lower is faster. Log scale on both axes.">
        <ResponsiveContainer width="100%" height={400}>
          <LineChart data={chartData} margin={{ top: 10, right: 30, left: 10, bottom: 10 }}>
            <CartesianGrid stroke="var(--border-subtle)" strokeDasharray="3 3" />
            <XAxis
              dataKey="size"
              scale="log"
              domain={['auto', 'auto']}
              stroke="var(--text-tertiary)"
              tick={{ fontFamily: 'var(--font-mono)', fontSize: 11, fill: 'var(--text-tertiary)' }}
              tickFormatter={(v) => (v >= 1048576 ? `${(v / 1048576).toFixed(0)}MB` : v >= 1024 ? `${(v / 1024).toFixed(0)}KB` : `${v}B`)}
            />
            <YAxis
              scale="log"
              domain={['auto', 'auto']}
              stroke="var(--text-tertiary)"
              tick={{ fontFamily: 'var(--font-mono)', fontSize: 11, fill: 'var(--text-tertiary)' }}
              label={{ value: 'ms (log scale)', angle: -90, position: 'insideLeft', fill: 'var(--text-tertiary)', fontSize: 11 }}
            />
            <Tooltip
              contentStyle={{ background: 'var(--bg-panel-raised)', border: '1px solid var(--border-strong)', fontFamily: 'var(--font-mono)', fontSize: 12 }}
              labelFormatter={(v) => `${v} bytes`}
            />
            <Legend wrapperStyle={{ fontSize: 12, fontFamily: 'var(--font-ui)' }} />
            {algorithms.map((algo) => (
              <Line
                key={algo}
                type="monotone"
                dataKey={algo}
                stroke={ALGO_COLORS[algo] || '#5B8DEF'}
                strokeWidth={2}
                dot={{ r: 2 }}
                connectNulls
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </Panel>

      <Panel title="Raw results" subtitle={`${data.results.length} (algorithm, payload size) combinations`}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Algorithm</th>
              <th>Payload size</th>
              <th>Mean total (ms)</th>
              <th>Throughput (MB/s)</th>
              <th>Repetitions</th>
            </tr>
          </thead>
          <tbody>
            {data.results.map((r, i) => (
              <tr key={i}>
                <td>{r.algorithm}</td>
                <td className="mono">{r.payload_size_bytes.toLocaleString()} B</td>
                <td className="mono">{r.total_operation_seconds?.mean != null ? (r.total_operation_seconds.mean * 1000).toFixed(4) : '—'}</td>
                <td className="mono">{r.throughput_mb_per_second?.mean != null ? r.throughput_mb_per_second.mean.toFixed(2) : '—'}</td>
                <td className="mono">{r.n_repetitions}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
