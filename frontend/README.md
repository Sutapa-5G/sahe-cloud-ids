# SAHE Cloud IDS Dashboard (Phase 13)

React + Vite dashboard for the SAHE Cloud IDS/IPS backend.

## Status

Built and verified via `npm run build` (a real, successful production
build — confirms every import/JSX/syntax path is correct) and `npx
oxlint` (0 errors). **Not visually verified in a browser** — the
sandbox this project was built in has no way to render and interact
with a live browser session. The person running this locally should do
that verification: `npm run dev` and click through each page.

## Setup

```bash
npm install
cp .env.example .env
# Edit .env if your backend isn't at http://localhost:8000

npm run dev
```

Requires the backend (Phase 9+) running separately — see
`../docs/methodology/backend_api.md`.

## Pages

- **Overview** — summary stats + recent alerts
- **Live Attacks** — full live WebSocket alert feed
- **Detection Analytics** — interactively call `/detect`
- **Crypto Analytics** — interactively call `/encrypt` / `/decrypt`
- **SAHE Decisions** — live policy preview via `/crypto/policy`
- **Benchmark Results** — real Phase 7 crypto benchmark data, charted
- **Firewall Actions** — view/block/unblock IPs via `/firewall/*`

## Design

See `../docs/methodology/dashboard.md` for the full design rationale
(dark, instrumentation-style palette; muted 4-step severity ramp; IBM
Plex Sans/Mono).

## Honesty in the UI

Per this project's no-fabrication discipline, every page shows an
explicit empty/error state rather than silently displaying blank or
zero data when the backend has nothing to show (e.g. no model loaded,
no benchmark data present, no alerts yet this session). See
`EmptyState.jsx`.
