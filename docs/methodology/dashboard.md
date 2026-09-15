# Dashboard, Integration & Docker (Phases 13, 14, 15)

## Status - read this first

This phase has a hard verification boundary, stated plainly:

| What | Verified how | Confidence |
|---|---|---|
| React dashboard code compiles/builds correctly | `npm run build` - a real, successful production build | High - a build failure would have caught any broken import/JSX |
| React dashboard has no lint errors | `npx oxlint src/` - 0 errors, 2 accepted warnings (standard "fetch on mount" pattern) | High |
| Backend CORS configuration actually works | Real test: allowed origin gets the CORS header, disallowed origin does not | High - genuinely executed |
| React dashboard actually renders correctly in a browser, looks as designed, layout doesn't break, interactions work | NOT verified - this sandbox cannot render or click through a live browser session | None - must be checked locally |
| docker-compose.yml is valid YAML with correct service/volume references | Parsed with PyYAML, all referenced file paths confirmed to exist | High |
| The 3 containers actually build successfully with `docker build` | NOT verified - no `docker` binary available in this sandbox | None - must be checked locally |
| The 3 containers actually start and talk to each other (`docker-compose up`) | NOT verified - same reason | None - must be checked locally |

This is the most significant "must verify locally" boundary in the
entire project so far. Everything else in this project (Python code,
backend, crypto) was executed and tested for real in this environment.
This phase's frontend/Docker code is real, carefully written, and
build-verified where a build was possible - but visual/runtime
verification requires tools this sandbox doesn't have.

## Phase 13: React Dashboard

### Design
See the design tokens in `frontend/src/index.css` for the full rationale
in comments. Summary: a dark, instrumentation-style palette (network
operations center, not consumer SaaS dashboard), a deliberately muted
4-step severity ramp (teal, amber, burnt orange, brick red - never
neon), IBM Plex Sans for UI text and IBM Plex Mono for all data values
(IPs, timestamps, ciphertext, hex). Left-rail navigation, dense tabular
layout rather than card-heavy spacing, matching how real console tools
(Grafana, Wireshark) present continuously-monitored data.

### Pages Built
1. Overview - summary stat tiles + recent alerts table
2. Live Attacks - full live WebSocket feed (all alerts this session)
3. Detection Analytics - interactive form calling the real `/detect`
   endpoint; correctly surfaces the honest 503 state when no model is
   loaded
4. Crypto Analytics - interactive encrypt/decrypt against the real
   `/encrypt`/`/decrypt` endpoints (requires the API auth token)
5. SAHE Decisions - live policy preview via the unauthenticated
   `/crypto/policy` endpoint, with size/severity/data-type controls
6. Benchmark Results - charts the REAL Phase 7 benchmark data
   (`experiments/results/crypto_benchmark_aggregated.json`) via Recharts;
   shows an explicit empty/error state if that file isn't present
7. Firewall Actions - view/block/unblock IPs via the real
   `/firewall/*` endpoints

### Honesty Discipline in the UI
Every page that depends on backend data has an explicit empty/error
state component (`EmptyState.jsx`) rather than silently rendering
nothing or a blank chart. Examples: "No alerts received yet this
session" (not a fabricated example alert), "No trained detection model
is loaded" surfaced verbatim from the backend's real 503 response,
"No benchmark data available" with instructions to run Phase 7 if the
file is missing. This mirrors the discipline enforced throughout the
Python codebase - the dashboard must not visually imply data exists
when it doesn't.

### What Was NOT Built
- No authentication/login screen for the dashboard itself - it assumes
  network-level access control (e.g. deployed behind a VPN) or that the
  operator manually enters the API bearer token per protected action
  (the pattern used on the Crypto Analytics and Firewall Actions pages).
  A production deployment should add a proper login flow.
- No alert history/backfill on WebSocket reconnect - a browser tab
  opened after an alert was broadcast won't see it (same limitation
  noted in Phase 11/12's docs).
- No dark/light theme toggle - the dark instrumentation palette is the
  only theme, a deliberate scope decision for this project.

## Phase 14: End-to-End Integration

### What Was Wired
- `frontend/src/api/client.js` - a single fetch-based client covering
  every backend endpoint used by the dashboard.
- `frontend/src/hooks/useLiveAlerts.js` - manages the WebSocket
  connection with automatic reconnection (3s delay) if the connection
  drops, and keeps the most recent 200 alerts in memory.
- CORS: found the backend had no CORS configuration at all while
  writing this documentation - a real gap that would have silently
  broken every browser request from the dashboard to the API. Fixed:
  `backend/app/config.py` gained `cors_allowed_origins` (configurable,
  defaults to the local dev/Docker frontend ports), and
  `backend/app/main.py` now adds `CORSMiddleware`. Verified for real
  with a test that confirms an allowed origin gets the
  `access-control-allow-origin` header and a disallowed one doesn't.
- `docker-compose.yml` - see Phase 15 below; this is what makes "the
  frontend talks to the backend talks to MongoDB" possible as a single
  `docker-compose up`, once verified locally.

### What This Phase Could NOT Verify
The core promise of "end-to-end integration" - that all three services
actually start, discover each other by container name (`mongodb`,
`backend`), and a browser hitting the frontend can genuinely exercise
the whole system live - requires running containers, which this sandbox
cannot do. See "Status" above and "How to Verify Locally" below.

## Phase 15: Docker Deployment

### What Was Built
```
backend/Dockerfile     - python:3.12-slim, installs backend/requirements.txt,
                          copies the whole repo (backend imports ml/ and
                          crypto/ as sibling packages)
frontend/Dockerfile    - multi-stage: node:22-slim build -> nginx:alpine serve,
                          with an SPA fallback (nginx.conf) so React Router's
                          client-side routes survive a direct page refresh
docker-compose.yml     - mongodb (official image, healthchecked),
                          backend (depends on mongodb being healthy),
                          frontend (depends on backend)
.dockerignore          - excludes node_modules, __pycache__, .git, etc.
```

### Design Decisions
- `backend` mounts `ml/models` and `experiments/results` read-only as
  volumes, rather than baking them into the image. This means a model
  trained locally (Phase 2/3, once real CICIDS2017 data is available) or
  a freshly re-run benchmark suite (Phase 7) becomes visible to the
  containerized backend without rebuilding the image - important for
  the iterative "train locally, verify in the full stack" workflow this
  project needs once real data exists.
- `API_AUTH_TOKEN` is read from the host environment
  (`${API_AUTH_TOKEN:-}`), never hardcoded in the compose file. An
  unset token means the backend's auth-protected routes correctly stay
  locked (fails closed, per Phase 9's design) rather than the compose
  file silently supplying an insecure default.
- MongoDB has a healthcheck, and `backend` uses
  `depends_on: condition: service_healthy` - so the backend's first
  connection attempt isn't racing against MongoDB still starting up
  (relevant given Phase 10's aggressive 500ms connection timeout, which
  was tuned for fast-fail against an ABSENT MongoDB, not a slow-starting
  one; the healthcheck avoids that conflict).

## How to Verify Locally (required before trusting Phases 13-15)

```bash
# 1. Frontend visual verification
cd frontend
npm install
npm run dev
# Open http://localhost:5173, click through all 7 pages, confirm the
# design renders as intended and interactions (forms, buttons) work.

# 2. Full Docker stack
cd ..
export API_AUTH_TOKEN=some-real-secret-value
docker compose up --build
# Confirm all three containers start without errors.
# Open http://localhost:5173 (frontend) and http://localhost:8000/docs
# (backend's OpenAPI UI) and confirm they're both reachable and the
# frontend's requests to the backend succeed (check the browser's
# network tab for any CORS or connection errors).

# 3. Confirm MongoDB is actually used (not the in-memory fallback)
curl -X POST http://localhost:8000/events \
     -H "Content-Type: application/json" \
     -d '{"attack_type": "DDoS", "severity": "HIGH"}'
# Check the response's "storage_backend" field - should say "mongodb",
# not "in_memory_fallback", confirming Phase 10's MongoDB integration
# works against a REAL MongoDB (finally verifiable, since docker-compose
# runs a real mongo:7 container).
```

## Testing

3 new backend tests (`test_cors.py`) - real, executed: confirms CORS
headers are present for an allowed origin and absent for a disallowed
one, and that the comma-separated origins list parses correctly.

Frontend: `npm run build` (successful) and `npx oxlint src/` (0 errors)
- see "Status" table above for exactly what this does and doesn't prove.

## Limitations

- Frontend has never been visually rendered or clicked through. This is
  the single most important caveat in this document. The design intent
  is documented and the code builds, but "does it actually look right
  and work when a human uses it" is unverified.
- No container has ever actually been built or run. The Dockerfiles and
  compose file are carefully written against real, confirmed file paths,
  but `docker build`/`docker compose up` have never executed.
- CORS is now configured, but only tested against FastAPI's TestClient
  - a real browser's preflight (OPTIONS) request behavior for
  non-simple requests (e.g. the `Authorization` header used by
  `/encrypt`) should be re-checked during local Docker verification.
- The dashboard's bundle size (652 KB JS, mostly Recharts) is cosmetic
  for a project of this scope but could be addressed with code splitting
  if it matters for the final deliverable.
