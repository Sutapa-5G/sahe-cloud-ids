# Backend API Methodology (Phase 9)

## Status

Fully implemented and tested — 41 backend tests pass, all executed for
real via FastAPI's TestClient (real HTTP request/response cycles against
a real running app instance, real crypto operations through the API,
real firewall state transitions). The only things NOT real here are:
(1) storage — MongoDB is unavailable in this environment, so `/events`
and the crypto envelope store use documented in-memory placeholders that
Phase 10 replaces; (2) the ML model — no real CICIDS2017-trained model
exists yet, so `/detect` correctly returns 503 in this checkout (verified
by a real test), and a separate test trains a real (if synthetic-data)
model to confirm the happy path also works correctly.

## What This Phase Built

```
backend/app/
├── main.py              - app factory, startup (key generation, model loading, etc.)
├── config.py            - pydantic-settings, typed config from .env
├── api/
│   ├── auth.py           - bearer-token auth dependency, FAILS CLOSED if unconfigured
│   └── routes/
│       ├── health.py
│       ├── detection.py  - /detect
│       ├── events.py     - /events (in-memory placeholder, Phase 10 replaces)
│       ├── crypto.py      - /encrypt, /decrypt, /crypto/policy
│       ├── firewall.py    - /firewall/block, /unblock, /rules
│       ├── benchmark.py   - /benchmarks (reads REAL Phase 7 data)
│       └── websocket.py   - /ws/events
├── audit/
│   └── audit_logger.py    - AuditLogger + InMemoryAuditSink (real) + MongoAuditSink (Phase 10 stub)
├── firewall/
│   └── provider.py        - SimulatedFirewallProvider (default) + IptablesFirewallProvider (opt-in)
├── websocket/
│   └── manager.py         - ConnectionManager, broadcast to all connected clients
└── schemas/
    ├── detection.py, crypto.py, firewall.py
```

## Design Decisions

### Auth fails closed
`require_auth` (the dependency protecting `/encrypt`, `/decrypt`,
`/firewall/block`, `/firewall/unblock`) returns **503**, not a silent
pass-through, if `api_auth_token` is unset in config. An unconfigured
deployment is a broken deployment, not an open one. Verified by
`test_encrypt_requires_auth` and the earlier manual TestClient run shown
in this conversation.

### Firewall defaults to simulated
`get_firewall_provider()` returns `SimulatedFirewallProvider` for
`"simulated"` mode AND for any unrecognized mode string — an unrecognized
config value never accidentally activates the real iptables path. Only
the literal string `"iptables"` does. Verified by
`test_get_firewall_provider_unknown_mode_defaults_to_simulated`.

`IptablesFirewallProvider` was tested in this sandbox (which lacks the
privileges to run real iptables) and correctly fails safely — returns
`success=False` with an error message rather than raising an uncaught
exception. This confirms the failure-handling code path works, but the
actual "does it correctly modify a real firewall" behavior remains
UNTESTED and must be verified on a real Linux host with appropriate
privileges before relying on it.

### In-memory placeholders, clearly documented
- `/events` uses an in-memory dict. Every route/test file says so.
- `/encrypt`'s envelope store is in-memory, keyed by a UUID. Restarting
  the backend process loses all encrypted envelopes — acceptable for
  this development phase, not for production.
- `MongoAuditSink.write()`/`read_all()` raise `NotImplementedError`
  explicitly (verified by a test) rather than silently no-op-ing, so a
  future integration mistake (forgetting to switch from InMemoryAuditSink)
  is loud, not silent.

### One server-wide keypair set
`_generate_server_keys()` in `main.py` generates one long-term
ECDH/RSA/Ed25519 keyset at startup, used for every `/encrypt` request in
this phase. A real multi-tenant deployment would need per-tenant or
per-purpose key management (Phase 10+ concern) — documented as a
simplification, not hidden.

### /detect fails clearly without a real model
`_load_detection_model()` returns `None` if neither
`ml/models/random_forest.joblib` nor `xgboost.joblib` exists — which is
the actual current state of this repository, since CICIDS2017 has never
been available to train on. `/detect` then returns a 503 with an
explicit, actionable message. This is verified by
`test_detect_returns_503_when_no_model_loaded`, run against the real
(model-less) checkout.

A SEPARATE test (`test_detection_with_real_model.py`) trains a real
`RandomForestClassifier` on small synthetic data, saves it, points the
app at it via `ML_MODEL_DIR`, and confirms the happy path works
end-to-end. This validates the route's code correctly serves a real
model when one exists — it does not and cannot validate real-world
detection accuracy, since the training data is synthetic.

## API Surface

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | /health | none | |
| POST | /detect | none | 503 if no model loaded |
| POST | /events | none | in-memory placeholder |
| GET | /events | none | |
| GET | /events/{id} | none | |
| POST | /encrypt | required | |
| POST | /decrypt | required | |
| POST | /crypto/policy | none | preview only, no real crypto/keys touched |
| POST | /firewall/block | required | |
| POST | /firewall/unblock | required | |
| GET | /firewall/rules | none | |
| GET | /benchmarks | none | reads real Phase 7 data |
| GET | /benchmarks/{algorithm} | none | |
| WS | /ws/events | none | broadcast-only from server |

`/events` and `/firewall/rules` being unauthenticated is a documented
choice appropriate for a development/demo phase — a production
deployment should reconsider which read endpoints need auth too.

## How to Run

```bash
pip install -r backend/requirements.txt
cp .env.example .env
# Set API_AUTH_TOKEN in .env to something real for local testing.

uvicorn backend.app.main:app --reload
```

Interactive API docs at `http://localhost:8000/docs` (FastAPI's
auto-generated OpenAPI UI).

## Testing

41 tests in `backend/tests/`, all executed as real HTTP requests against
a real running FastAPI app (via TestClient, which runs the actual ASGI
app in-process — this is genuine integration testing, not mocked):

- `test_health.py` (1)
- `test_crypto_routes.py` (9) — including a real encrypt-then-decrypt
  round-trip through the HTTP API, auth enforcement, AUDIT+CRITICAL
  signature verification through the API
- `test_firewall_routes.py` (5) — real block/unblock state transitions
- `test_firewall_provider.py` (8) — including the iptables fail-safe test
- `test_detection_routes.py` (1) — the critical 503-when-no-model test
- `test_detection_with_real_model.py` (2) — real model trained on
  synthetic data, exercised through the API
- `test_events_routes.py` (3)
- `test_benchmark_routes.py` (3) — reads REAL Phase 7 data; skips (not
  fails) if that data isn't present in a given checkout
- `test_audit_logger.py` (5) — including confirming MongoAuditSink
  honestly raises NotImplementedError
- `test_websocket.py` (3) — real WebSocket connection test plus direct
  ConnectionManager broadcast/cleanup tests

Run with:

```bash
python -m pytest backend/tests/ -v
```

## Limitations

- No real MongoDB integration — `/events` and the crypto envelope store
  are in-memory and lost on restart. Phase 10's job.
- No Redis — deliberately deferred per original project scope.
- `IptablesFirewallProvider`'s actual firewall-modification behavior is
  untested against a real iptables installation (this sandbox lacks the
  privileges). Must be verified on real deployment hardware before
  relying on it, and should probably get its own integration test suite
  run in a privileged container at that point.
- Auth is a single shared bearer token, not per-user/per-role. Adequate
  for this phase's scope; a real multi-user deployment needs a proper
  auth system (JWT/OAuth2), and `auth.py`'s docstring says so.
- `/detect` only accepts pre-extracted numeric features (matching Phase
  1's processed feature space) — it does not parse raw packets. Live
  traffic capture (Scapy) integration, if pursued, is a `nice-to-have`
  per the original phase scoping.
- The one-server-wide-keypair simplification means this phase cannot
  yet demonstrate per-tenant key isolation, which a production cloud IDS
  serving multiple customers would need.
