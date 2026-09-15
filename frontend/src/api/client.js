const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

class ApiError extends Error {
  constructor(message, status, detail) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!res.ok) {
    let detail = null;
    try {
      const body = await res.json();
      detail = body.detail;
    } catch {
      // response wasn't JSON — leave detail null
    }
    throw new ApiError(
      detail || `Request to ${path} failed with status ${res.status}`,
      res.status,
      detail
    );
  }

  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  health: () => request('/health'),

  detect: (payload) =>
    request('/detect', { method: 'POST', body: JSON.stringify(payload) }),

  listEvents: () => request('/events'),
  getEvent: (id) => request(`/events/${id}`),

  cryptoPolicyPreview: (payload) =>
    request('/crypto/policy', { method: 'POST', body: JSON.stringify(payload) }),

  encrypt: (payload, token) =>
    request('/encrypt', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers: { Authorization: `Bearer ${token}` },
    }),

  decrypt: (envelopeId, token) =>
    request('/decrypt', {
      method: 'POST',
      body: JSON.stringify({ envelope_id: envelopeId }),
      headers: { Authorization: `Bearer ${token}` },
    }),

  listFirewallRules: () => request('/firewall/rules'),
  blockIp: (ip, reason, token) =>
    request('/firewall/block', {
      method: 'POST',
      body: JSON.stringify({ ip, reason }),
      headers: { Authorization: `Bearer ${token}` },
    }),
  unblockIp: (ip, token) =>
    request('/firewall/unblock', {
      method: 'POST',
      body: JSON.stringify({ ip }),
      headers: { Authorization: `Bearer ${token}` },
    }),

  getAllBenchmarks: () => request('/benchmarks'),
  getBenchmarkFor: (algorithm) => request(`/benchmarks/${algorithm}`),
};

export { ApiError, API_BASE };
