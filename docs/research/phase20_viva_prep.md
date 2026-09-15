# Phase 20 Viva Preparation

## Core one-minute explanation

This project is a defensive cloud IDS/IPS prototype. It classifies network-flow records with machine-learning pipelines and then protects the resulting alerts, logs, files, and audit records with SAHE. SAHE means Size-and-Severity Adaptive Hybrid Encryption, but it is a **policy framework**, not a new cipher. AES-256-GCM always encrypts payload bytes. X25519/ECDH and RSA-OAEP only establish or wrap the AES key. Ed25519 is used only for critical audit records that need non-repudiation. The prototype connects detection, severity, cryptographic policy, real-time alerts, simulated firewall blocking, persistence, and a dashboard.

## Anticipated questions and answers

### Why is SAHE not a new cipher?

Because it does not change AES, X25519, RSA, or Ed25519. It selects established mechanisms and operational requirements based on payload size, threat severity, and data type. The payload cipher remains AES-256-GCM in every path.

### Why is AES-GCM used for every payload?

GCM provides authenticated encryption. It is appropriate for protecting confidentiality and integrity together. Public-key operations are not used on arbitrary payload bytes because they are key-management mechanisms in this architecture.

### Why not add HMAC for every high-severity event?

The GCM authentication tag already authenticates ciphertext to a holder of the shared AES key. A blanket second MAC would add complexity without addressing the specific requirement. A digital signature is added only for a critical audit record when a third-party verifier may not possess the shared AES key.

### Why are both ECDH and RSA included?

They express different deployment trade-offs. X25519/ECDH supports ephemeral shared-secret establishment and forward secrecy when used with an appropriate key lifecycle. RSA-OAEP fits established PKI and certificate infrastructure. The policy keeps both available rather than assuming that one is universally best.

### What did the benchmark show?

The existing Phase 7 output contains 330 raw measurements across eleven payload sizes and six algorithms. The Phase 8 analysis found no ECDH/RSA speed crossover. RSA-OAEP-Hybrid had lower measured total operation time at every tested size on that machine. The new policy-regret diagnostic found that the default policy matched the performance-only fastest option at 4 of 11 sizes, or 36.36%. This result is hardware-specific and does not measure forward secrecy or operational compatibility.

### Does the 36.36% result mean the policy is wrong?

No. It means the policy is not optimized for the single elapsed-time metric used by the oracle. The code explicitly retains ECDH below the large threshold for a forward-secrecy rationale and does not claim a speed advantage. The correct next step is a multi-objective deployment-hardware study.

### Did you obtain real CICIDS2017 accuracy?

No. The dataset was not available in the execution environment. Preprocessing and model code were tested with synthetic fixtures, but those tests are not research findings. Real accuracy, precision, recall, F1, ROC-AUC, row counts, and class distributions are **NOT EXECUTED YET**.

### Why use synthetic data in tests?

Synthetic fixtures allow software contracts to be tested without pretending to be the real dataset. Test names, docstrings, and documentation label those fixtures as synthetic so their outputs cannot be confused with CICIDS2017 results.

### Can the system modify a real firewall?

The default is simulated mode. The provider abstraction includes a separate opt-in iptables provider with validation and audit logging. The project does not silently modify a host firewall.

### What happens if MongoDB is unavailable?

The application attempts the configured MongoDB connection, detects failure, and uses the documented in-memory fallback. API responses identify the storage backend. A real MongoDB server was not available in the original execution environment, so production trust still requires local verification.

### Is the Docker deployment verified?

The YAML and referenced paths were validated, but Docker was not installed in the environment. Container builds and the multi-container runtime are therefore **NOT EXECUTED YET**.

### What is the most important limitation?

The missing real CICIDS2017 dataset prevents a scientific claim about IDS accuracy. The project is a tested prototype and reproducible crypto-analysis package, not a completed real-data evaluation.

## Demonstration order for a local viva

1. Show the architecture and explain the ML → severity → SAHE → alert/firewall path.
2. Start MongoDB, backend, and frontend locally and verify the health endpoint.
3. Open the dashboard and show explicit empty/error states before loading data.
4. Demonstrate a benign detection and a malicious detection with a correlation ID.
5. Show that a high-severity detection with a source IP creates a simulated firewall action.
6. Demonstrate AES-GCM round-trip and tamper rejection.
7. Show the SAHE decision for a normal record and a critical audit record.
8. Run the benchmark-analysis script and explain the RSA/ECDH negative finding.
9. If the dataset is available, run the ML pipeline and update the report with preserved real outputs.

## Claims to avoid

Do not say that the model is accurate without real CICIDS2017 metrics. Do not call SAHE a new encryption algorithm. Do not say ECDH is faster because the existing measurement contradicted that assumption. Do not describe DES, 3DES, or Blowfish as recommended security choices. Do not say Docker deployment is verified until it has been built and run locally.
