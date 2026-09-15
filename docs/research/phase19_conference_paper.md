# SAHE Cloud IDS/IPS: A Threat-Aware Policy Framework for Protecting Cloud Intrusion-Detection Records

**Short conference-paper draft**  
**Authors:** Sutapa Giorai, Tanushree Mondal, Kaushani Koner  
**Supervisor:** Dr. Deepa Naik

## Abstract

Cloud intrusion-detection systems produce alerts and evidence that must remain confidential, intact, and attributable while moving through storage and service boundaries. This paper presents SAHE, a size-and-severity adaptive cryptographic **policy framework** integrated with a machine-learning IDS/IPS prototype. SAHE does not introduce a cipher. AES-256-GCM always encrypts payload bytes. X25519 with HKDF and RSA-OAEP establish or wrap the data-encryption key, while Ed25519 is reserved for critical audit records that require non-repudiation. The prototype includes preprocessing, Random Forest and XGBoost training paths, severity mapping, FastAPI APIs, MongoDB repositories, WebSocket alerts, simulated firewall blocking, a React dashboard, and Docker deployment configuration.

The real CICIDS2017 dataset was unavailable during this execution, so no real ML accuracy result is reported. Existing measured cryptographic benchmark output covers eleven payload sizes from 1 KiB to 100 MiB and six algorithms. A reproducible analysis script computed a performance-only policy-selection diagnostic: the default policy matched the fastest measured feasible key-establishment option at 4 of 11 sizes (36.36%) on the benchmark machine. That figure is not a security score and should not be generalized to other hardware. The main contribution is therefore a testable integration architecture and an explicit evidence boundary, not an unsupported claim of universal performance improvement.

**Keywords:** intrusion detection, cloud security, authenticated encryption, adaptive policy, X25519, RSA-OAEP, Ed25519, CICIDS2017

## 1. Introduction

Network IDS research often evaluates detection quality separately from protection of the resulting alerts and records. In a cloud deployment, that separation leaves a practical gap: a detection may be correct, but the evidence can still be exposed or altered after inference. This work addresses the boundary by connecting flow classification to a policy that selects key-management and authenticity requirements for the resulting data.

CIC-IDS2017 provides labeled benign and attack traffic and flow features for IDS evaluation.[1] The dataset is the intended input for this prototype, but it was not available in the execution environment. The paper consequently distinguishes executable software validation from real-data scientific evaluation.

## 2. Related technical basis

GCM is standardized as authenticated encryption with associated data.[2] The project uses AES-256-GCM for payload confidentiality and integrity. X25519 is specified for Diffie–Hellman-style key agreement and subsequent symmetric-key derivation.[3] Ed25519 is specified as an EdDSA signature scheme with deterministic signing properties.[4] These standards support the division of responsibilities used by SAHE; they do not establish any claim that the policy itself is a new cryptographic primitive.

## 3. SAHE policy and system

The policy consumes payload size, severity, and data type. Severity affects response requirements rather than the mathematical strength of a cipher. AES-GCM's native tag is used by default. An Ed25519 signature is added only for an AUDIT record at CRITICAL severity, where a third-party auditor may need to verify origin without holding a shared AES key.

For key establishment, the current policy retains ECDH/X25519 below the configurable large-payload threshold and selects RSA-OAEP at or above that threshold. The repository documentation states that this retained switch is an operational and PKI-compatibility choice, not a measured speed advantage. The system defaults to simulated firewall actions and fails closed when its optional API token is not configured.

## 4. Implementation and evaluation method

The implementation is organized into preprocessing, model training, severity, cryptography, backend, storage, alerting, firewall, and dashboard modules. Unit and integration tests use synthetic fixtures where the real dataset is unavailable. Cryptographic tests execute real AES-GCM, X25519, RSA-OAEP, HKDF, and Ed25519 operations.

The Phase 16–17 analysis script reads `experiments/results/crypto_benchmark_aggregated.json`. It generates total-operation-time, throughput, and ciphertext-expansion plots. It also computes policy regret against a narrow oracle that chooses the measured fastest feasible key-establishment option for each payload size. The oracle does not encode forward secrecy, PKI compatibility, certificate operations, or non-repudiation.

## 5. Results

The source file contains 66 aggregated rows covering six algorithms and eleven payload sizes. The approved algorithms are AES-256-GCM, ECDH-X25519-Hybrid, and RSA-OAEP-Hybrid. DES, 3DES, and Blowfish are historical baselines only.

| Result | Observed value | Evidence scope |
|---|---:|---|
| Aggregated benchmark rows | 66 | Existing Phase 7 measured output |
| Payload-size points | 11 | 1 KiB through 100 MiB |
| ECDH/RSA speed crossover | None observed | Existing Phase 8 analysis on one machine |
| Default-policy matches to fastest feasible option | 4 / 11 | New deterministic analysis of existing output |
| Performance-only selection accuracy | 36.36% | Not a security or production-readiness score |
| Real CICIDS2017 model metrics | NOT EXECUTED YET | Dataset unavailable |
| Docker multi-container run | NOT EXECUTED YET | Docker unavailable in the environment |

The benchmark contradicts the earlier assumption that ECDH would be faster at small and medium payload sizes. RSA-OAEP-Hybrid had lower measured total operation time at every compared size. The implementation retains ECDH below the large threshold for the documented forward-secrecy rationale, which is not represented by the elapsed-time oracle.

## 6. Discussion

The result demonstrates why an adaptive policy must not be justified by an untested crossover assumption. A policy can reasonably choose a slower operation when it protects a security property that the benchmark metric omits, but that trade-off must be stated. The appropriate next experiment is therefore multi-objective: repeat the benchmark on deployment hardware and add explicit measurements or qualitative controls for key lifecycle, certificate infrastructure, forward secrecy, and operational compatibility.

No conclusion about IDS accuracy can be drawn from this delivery. Synthetic tests show that the ML pipeline executes and that its evaluation code handles expected inputs. They do not substitute for a real CICIDS2017 run. Reporting a fabricated accuracy would weaken, rather than strengthen, the paper.

## 7. Limitations and reproducibility

The principal limitation is the missing dataset. Further limitations are the single-machine benchmark environment, the unverified Docker runtime, and the absence of visual browser verification for the dashboard. The repository includes the analysis script, raw and aggregated benchmark outputs, generated plots, and a JSON summary so that a local run can be compared with this draft.

To reproduce the crypto analysis, install the backend requirements and run:

```bash
python experiments/scripts/phase16_17_analysis.py
```

To complete the ML evaluation, place the official CICIDS2017 CSV files in `ml/data/raw/`, run the documented preprocessing and training commands, and preserve the generated metrics. The resulting paper must update only the evidence-labeled sections.

## 8. Conclusion

SAHE provides an auditable policy layer that connects IDS severity to cryptographic handling without claiming to be a new cipher. The prototype demonstrates the integration path and reports an honest negative benchmark finding: RSA was faster than ECDH at every measured size on the available hardware. The real-data detection evaluation and containerized deployment remain open experiments, not hidden assumptions.

## References

[1]: https://www.unb.ca/cic/datasets/ids-2017.html "Canadian Institute for Cybersecurity, Intrusion detection evaluation dataset (CIC-IDS2017)"
[2]: https://csrc.nist.gov/pubs/sp/800/38/d/final "NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
[3]: https://www.rfc-editor.org/rfc/rfc7748.html "RFC 7748, Elliptic Curves for Security"
[4]: https://www.rfc-editor.org/rfc/rfc8032.html "RFC 8032, EdDSA: Ed25519 and Ed448"
