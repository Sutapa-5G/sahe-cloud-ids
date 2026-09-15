# SAHE Cloud IDS/IPS

Cloud-Based Intrusion Detection and Prevention System with Threat-Aware
Adaptive Cryptographic Policy (SAHE).

## Status
Phase 0 — repository scaffolding. No executable functionality yet.

## Core Concept

SAHE (Size-and-Severity Adaptive Hybrid Encryption) is **not a new cipher**.
It is an adaptive cryptographic *policy framework*:

- AES-256-GCM always performs actual payload encryption.
- ECC / RSA are used only for key exchange, key-wrapping, or signing —
  never to encrypt arbitrary payload data directly.
- Threat severity affects the *security policy* (integrity, authentication,
  signing, key-management requirements) — it does NOT change the
  mathematical strength of any cipher.

## Research Questions

1. **RQ1 (IDS):** How accurately can ML models detect and classify attacks
   in cloud network traffic?
2. **RQ2 (Crypto):** How does the adaptive SAHE policy perform compared to
   static encryption / static hybrid schemes across payload sizes?
3. **RQ3 (Integration):** Does threat-aware adaptive cryptographic
   selection reduce overhead while preserving confidentiality, integrity,
   and authenticity?

SAHE is evaluated against this hypothesis — not assumed to win. See
`experiments/results/` for real measured output once available, and
`docs/research/` for the honest writeup of whether the hypothesis held.

## Repository Structure

See `docs/architecture/` for the full architecture diagram and module
dependency graph.

- `backend/` — FastAPI service (ML inference, SAHE engine, storage, API)
- `frontend/` — React dashboard (Phase 13+)
- `ml/` — CICIDS2017 preprocessing, training, evaluation (standalone)
- `crypto/` — cryptographic primitives + SAHE policy engine (standalone)
- `firewall/` — blocking abstraction (simulated by default)
- `experiments/` — benchmark scripts and real measured results
- `docs/` — architecture, methodology, API docs, research writeup

## Development Method

Built incrementally, phase by phase (see `docs/architecture/phases.md`).
Each phase is implemented, tested, and confirmed working before the next
begins. No experimental result in this repo is fabricated — anything not
yet executed is explicitly marked `NOT EXECUTED YET` rather than invented.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env
# Fill in .env with your local MongoDB URI etc.
```

MongoDB and the CICIDS2017 dataset are NOT bundled in this repo — you must
provide them locally (see `ml/data/README.md` and `.env.example`).

## Safety Note

The firewall/blocking module defaults to **simulated mode**. It never
modifies your host firewall unless explicitly configured to do so. This
is a defensive research project, not an offensive security tool.
