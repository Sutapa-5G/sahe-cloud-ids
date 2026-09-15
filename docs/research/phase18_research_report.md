# SAHE Cloud IDS/IPS: Research Report

**Project:** Cloud-Based Intrusion Detection and Prevention System with Threat-Aware Adaptive Cryptographic Policy  
**Internal name:** Size-and-Severity Adaptive Hybrid Encryption (SAHE)  
**Authors:** Sutapa Giorai, Tanushree Mondal, Kaushani Koner  
**Supervisor:** Dr. Deepa Naik  
**Institution:** Dr. B C Roy Engineering College, Durgapur  
**Evidence boundary:** This report separates executed measurements, synthetic-validation-only implementation tests, and work that remains **NOT EXECUTED YET**.

## Abstract

This project develops a defensive prototype that combines machine-learning intrusion detection with an adaptive cryptographic policy for protecting alerts, logs, files, and audit records. The machine-learning component is designed for CICIDS2017 flow data. The cryptographic component, SAHE, is explicitly a policy framework rather than a new cipher. AES-256-GCM is the only primitive used to encrypt payload bytes. X25519-based ECDH with HKDF and RSA-OAEP are restricted to key establishment or key wrapping. Ed25519 signatures are added only for critical audit records when non-repudiation is required.

The repository contains implemented and tested preprocessing, Random Forest and XGBoost training paths, severity classification, cryptographic primitives, policy execution, a FastAPI backend, MongoDB repository integration, WebSocket alerts, simulated firewall blocking, a React dashboard, and Docker deployment configuration. The real CICIDS2017 files were not available in the execution environment. Consequently, no real IDS accuracy, class-distribution, row-count, or leakage result is reported here. Existing cryptographic benchmark output contains 330 raw measurements across eleven payload sizes and six algorithms from an earlier Phase 7 run. The new Phase 16–17 analysis consumes those measured outputs and calculates a performance-only policy-selection diagnostic. Under the default policy modeled in the repository, the selected key-establishment method matched the measured fastest feasible option at 4 of 11 payload sizes, or 36.36%. This is not a security score and must be rerun on deployment hardware before being treated as authoritative.

## 1. Introduction

Cloud-hosted services generate network events, alerts, logs, and audit records that require both timely detection and trustworthy protection. An intrusion-detection system can identify suspicious traffic, but the resulting evidence may itself be exposed, altered, or difficult to authenticate when moved between services. This project addresses the integration boundary between detection and protection.

CIC-IDS2017 is an official labeled network-flow benchmark that includes benign traffic and several common attack families, including brute force, denial of service, web attacks, infiltration, botnet, and distributed denial of service traffic.[1] The project uses that dataset as its intended ML input, but the dataset was not present in the execution environment used for this delivery.

The cryptographic design follows a strict division of responsibilities. Authenticated symmetric encryption protects payload bytes. Public-key mechanisms establish or wrap the symmetric key. A signature is a separate authenticity mechanism for the narrow case in which an external auditor must validate an audit record without possessing the shared encryption key. This separation prevents the policy layer from being mistaken for a new cipher.

## 2. Problem statement and research questions

A practical IDS/IPS prototype must answer three connected questions. First, can flow-based models classify malicious traffic with useful accuracy? Second, can a policy choose among established key-management options as payload size, severity, and data type change? Third, can the resulting system preserve confidentiality, integrity, and authenticity without introducing unjustified cryptographic overhead?

The project evaluates the following research questions:

- **RQ1:** How accurately can Random Forest and XGBoost detect and classify attacks in cloud network traffic?
- **RQ2:** How does the SAHE policy compare with static hybrid schemes across payload sizes?
- **RQ3:** Does threat-aware adaptive selection reduce overhead while preserving confidentiality, integrity, and authenticity?

The questions are evaluated rather than assumed to have positive answers. In particular, the existing benchmark contradicted the earlier expectation that ECDH would be faster than RSA on small and medium payloads on the benchmark machine.

## 3. Design principles

SAHE does not modify the mathematical strength of AES, X25519, RSA, or Ed25519 according to severity. Severity changes policy requirements. A high-severity event may trigger conservative firewall handling and a stronger operational response, but it does not make AES-256-GCM a different cipher.

AES-GCM supplies authenticated encryption. NIST describes GCM as authenticated encryption with associated data, which provides confidentiality and authentication for the protected data and associated metadata.[2] The implementation therefore does not add a blanket HMAC layer to high-severity records.

X25519 is used for ECDH-style key agreement. RFC 7748 describes the exchange of public values, computation of a shared secret, and subsequent derivation of a symmetric key.[3] RSA-OAEP is used to wrap a generated symmetric key. Neither public-key mechanism encrypts the application payload directly.

Ed25519 is used only when the policy identifies a critical audit record requiring non-repudiation to a third party. RFC 8032 specifies the Ed25519 signature scheme and describes deterministic signing and verification properties.[4]

## 4. System architecture

The pipeline begins with flow-data discovery, cleaning, deduplication, feature selection, and leakage checks. The resulting data can be used to train Random Forest and XGBoost models. The inference service maps a model prediction and confidence to a severity level. The severity and record metadata then enter the SAHE policy engine, which selects key establishment, determines whether a signature is required, and produces an auditable rationale.

The FastAPI backend exposes health, detection, event, crypto, benchmark, firewall, and WebSocket interfaces. MongoDB repositories are available for events, benchmarks, firewall actions, and audit logs. When MongoDB is unavailable, the service uses its documented in-memory fallback and labels the storage backend in responses. The firewall abstraction defaults to simulated mode and does not modify a host firewall unless explicitly configured.

The React dashboard consumes real backend endpoints and provides views for overview status, live attacks, detection analytics, cryptographic analytics, SAHE decisions, benchmark results, and firewall actions. The deployment configuration includes MongoDB, backend, and frontend services. Container builds and multi-container runtime integration remain unverified in this environment because Docker is not installed.

## 5. Methods and evidence status

The repository's preprocessing and model code has been exercised with synthetic fixtures. Those tests verify software behavior such as cleaning, splitting, leakage checks, training interfaces, and metric computation. They do not estimate performance on CICIDS2017.

The cryptographic primitives and SAHE execution path were tested using real cryptographic operations. The earlier benchmark measured the repository's crypto implementations on the sandbox hardware. The new analysis script, `experiments/scripts/phase16_17_analysis.py`, reads the existing aggregated benchmark file, generates plots, writes a policy-regret table, and emits a JSON summary. It does not generate new ML data or silently replace unavailable measurements.

The complete benchmark input contains 66 aggregated rows: eleven payload sizes for each of six algorithms. The approved design algorithms are AES-256-GCM, ECDH-X25519-Hybrid, and RSA-OAEP-Hybrid. DES, 3DES, and Blowfish are retained only as historical comparison baselines and are not security recommendations.

## 6. Executed benchmark analysis

The analysis used the existing Phase 7 measurements rather than claiming a new deployment-hardware run. The payload sizes span 1 KiB to 100 MiB. The Phase 8 threshold analysis found no ECDH/RSA speed crossover in the measured range; RSA-OAEP-Hybrid had lower measured total operation time at every listed payload size on that hardware.

For the performance-only selection diagnostic, the repository's default policy was modeled as ECDH-X25519-Hybrid below the 1 MiB large-payload threshold and RSA-OAEP-Hybrid at or above that threshold. The measured fastest feasible option was RSA at all eleven sizes in the available comparison. Therefore, the default policy matched the performance-only oracle at four of eleven sizes, yielding **36.36% selection accuracy** under this narrow definition. The seven mismatches are not automatically policy failures because the implementation documents forward secrecy as a reason to retain ECDH below the large threshold, while the oracle measures only elapsed operation time.

The result has three limitations. It was measured on one sandbox machine. It excludes a complete deployment cost model, including key lifecycle, certificate infrastructure, network latency, and operational risk. It also does not assign a numerical value to forward secrecy or non-repudiation. The correct conclusion is therefore that the policy should be revisited with deployment-hardware measurements and an explicit multi-objective cost function, not that RSA should replace ECDH everywhere.

## 7. ML evaluation status

Real CICIDS2017 evaluation is **NOT EXECUTED YET**. The repository contains no authoritative real-data accuracy, precision, recall, F1, ROC-AUC, row-count, class-distribution, or leakage result. Synthetic tests are labeled as synthetic and are not used as research findings. The next valid ML step is to place the official CSV files in `ml/data/raw/`, run preprocessing, train both models, preserve the generated JSON outputs, and then execute a separate real-data analysis.

## 8. Limitations

The first limitation is data availability. Without the real dataset, the IDS research question cannot be answered. The second limitation is runtime verification: Docker is unavailable in the execution environment, so the service stack has not been built or run as containers. The third limitation is visual verification: the dashboard has passed its build and lint checks, but it has not been clicked through in a real browser in this environment. The fourth limitation is deployment representativeness: the crypto benchmark reflects one machine and one software environment.

These limitations are part of the result. They prevent the report from making claims that the available evidence cannot support.

## 9. Future work

The immediate next step is a controlled local run with CICIDS2017 and real deployment hardware. The run should preserve the preprocessing manifest, class distribution, model metrics, confusion matrices, ROC-AUC calculations, and environment information. The crypto benchmark should be repeated on the target host with the same payload sizes and repetitions. The policy should then be evaluated under an explicit cost function that records latency, CPU, memory, storage expansion, key-management properties, and security requirements separately.

The Docker stack should be built and run locally with a real MongoDB instance. The dashboard should then be exercised page by page, including empty, error, WebSocket, detection, and firewall states. Finally, the model and benchmark outputs should be inserted into the report without replacing the evidence-status labels.

## 10. Conclusion

The project delivers a tested prototype architecture that connects ML detection, severity reasoning, adaptive cryptographic policy, real-time alerts, simulated prevention, persistent-storage integration, and a dashboard. Its most important design conclusion is conceptual: SAHE is a policy framework, not a new encryption algorithm. Its most important empirical conclusion is methodological: the earlier speed assumption favoring ECDH was contradicted by the measured benchmark, and the code and documentation were corrected instead of hiding the negative finding.

The remaining scientific conclusion is deliberately conditional. The crypto analysis is executed for the existing benchmark output, while real IDS accuracy and containerized deployment remain **NOT EXECUTED YET**. Completing those runs locally is necessary before making final claims about detection performance or production readiness.

## References

[1]: https://www.unb.ca/cic/datasets/ids-2017.html "Canadian Institute for Cybersecurity, Intrusion detection evaluation dataset (CIC-IDS2017)"
[2]: https://csrc.nist.gov/pubs/sp/800/38/d/final "NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
[3]: https://www.rfc-editor.org/rfc/rfc7748.html "RFC 7748, Elliptic Curves for Security"
[4]: https://www.rfc-editor.org/rfc/rfc8032.html "RFC 8032, EdDSA: Ed25519 and Ed448"
