# Architecture Overview

## Data Flow

```
CICIDS2017 / Scapy traffic
        |
        v
Traffic Ingestion
        |
        v
Feature Extraction
        |
        v
ML Detection (RF / XGBoost, LSTM optional)
        |
        v
Attack Type + Confidence
        |
        v
Severity Engine (rule-based, documented — not raw confidence)
        |
   +----+----+
   |         |
BENIGN   MALICIOUS
   |         |
   v         v
Normal     Alert Engine (WebSocket)
Logging       |
              v
        SAHE Policy Engine
              |
      +-------+-------+
      |               |
 AES-256-GCM      ECC/RSA
 (payload)        (key management / signing only)
      |               |
      +-------+-------+
              |
              v
       Encrypted MongoDB
              |
       +------+------+
       |             |
       v             v
   Dashboard     Block Engine
                    |
             Simulated (default) / iptables
```

## Module Dependency Graph

```
config.py <- everything

database/mongodb.py <- database/repositories.py <- services/*

crypto/aes_gcm.py     \
crypto/ecc.py          >- crypto/sahe.py <- services/encryption_service.py
crypto/rsa.py          /
crypto/signatures.py  /

ml/preprocessing.py \
ml/inference.py      >- services/detection_service.py
ml/severity.py       /

firewall/interface.py  \
firewall/simulator.py   >- services/blocking_service.py
firewall/iptables.py   /

services/* <- api/routes/*

websocket/manager.py <- api/routes/websocket.py, services/alert_service.py
```

Crypto and ML modules are independently testable with zero dependency on
FastAPI or MongoDB. This is intentional: Phases 1-8 are built and verified
standalone before backend wiring begins (Phase 9+).

## Key Design Rules (do not violate these while building later phases)

1. AES-256-GCM is the only mechanism that encrypts payload bytes directly.
2. ECC and RSA are used only for key exchange, key-wrapping, or signatures.
3. Severity changes the *policy* (integrity/auth/signing requirements),
   never the cipher's mathematical strength.
4. SAHE thresholds (small/large payload cutoffs) are configurable and must
   be derived experimentally in Phase 8 — never hardcoded as assumptions.
5. Firewall blocking defaults to simulated mode. Real iptables/AWS
   integration requires explicit opt-in configuration.
6. Encryption keys are never stored alongside ciphertext.
7. No experimental result is reported unless it was actually executed.
   Unexecuted work is labeled "NOT EXECUTED YET", not invented.
