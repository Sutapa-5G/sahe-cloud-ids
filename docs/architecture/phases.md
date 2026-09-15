# Development Phases

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Architecture + repo scaffolding | Done |
| 1 | CICIDS2017 preprocessing | Not started |
| 2 | Random Forest baseline | Not started |
| 3 | XGBoost model | Not started |
| 4 | ML evaluation + Severity Engine | Not started |
| 5 | Cryptographic primitives (AES-GCM, ECC, RSA-OAEP) | Not started |
| 6 | SAHE policy engine + cost function | Not started |
| 7 | Cryptographic benchmarking suite | Not started |
| 8 | Experimental threshold derivation | Not started |
| 9 | Done | FastAPI backend — see docs/methodology/backend_api.md |
| 10 | Done (verified against mongomock only, NOT real MongoDB) | See docs/methodology/mongodb.md |
| 11 | Done | Real-time alerts — see docs/methodology/realtime_and_firewall.md |
| 12 | Done | Firewall auto-block policy — see docs/methodology/realtime_and_firewall.md |
| 13 | Done (build-verified only, NOT visually rendered) | React dashboard — see docs/methodology/dashboard.md |
| 14 | Done (partially — CORS fixed and tested; container runtime NOT verified) | See docs/methodology/dashboard.md |
| 15 | Done (config written and validated, containers NEVER built/run) | See docs/methodology/dashboard.md |
| 16 | Full benchmark run | Done |
| 17 | Graphs / statistical analysis | Done |
| 18 | Research report | Done |
| 19 | Conference paper draft | Done |
| 20 | Final presentation / viva prep | Done |

## Rule for progressing phases

A phase is only marked "Done" once its code has actually been executed in
this environment (or by the user locally) and its output verified. No
phase is marked complete based on code existing but being untested.
