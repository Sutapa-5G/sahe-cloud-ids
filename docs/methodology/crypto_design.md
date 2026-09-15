# Cryptographic Design (Phases 5 & 6)

## Status

All primitives and the SAHE policy/engine are implemented and **fully
tested with real cryptographic operations** — 49 tests, 100% passing,
zero synthetic-fixture substitutes, since crypto correctness does not
depend on CICIDS2017 at all. This is the one part of the project that
can be considered complete and verified end-to-end at this stage,
independent of dataset availability.

## Design Rules (unchanged from Phase 0, now implemented)

1. **AES-256-GCM is the only mechanism that encrypts payload bytes
   directly**, anywhere in this system (`crypto/algorithms/aes_gcm.py`).
2. **ECC (ECDH/X25519) and RSA are used only for key
   establishment/wrapping**, never for direct payload encryption
   (`ecdh_x25519.py`, `rsa_oaep_hybrid.py`).
3. **Severity affects policy, not cipher strength.** The SAHE policy
   engine (`crypto/sahe/policy.py`) decides key-establishment method and
   whether a signature is warranted — it never asks AES/ECC/RSA to be
   "more secure" for a given severity.
4. **No blanket HMAC-on-GCM stacking.** AES-GCM's native tag is treated
   as sufficient authentication by default. A signature is added only
   for the one specific case where GCM's tag is insufficient: AUDIT-type
   records at CRITICAL severity, where non-repudiation to a third party
   without the shared AES key is needed.
5. **Encryption keys are never stored alongside ciphertext.** The
   `SaheEnvelope` dataclass stores the wrapped key / ECDH context (which
   are safe to store, since recovering the AES key from them requires the
   recipient's private key) — never the raw AES key itself.

## Primitives (crypto/algorithms/)

| Module | Purpose | Library primitive used |
|---|---|---|
| `aes_gcm.py` | Payload encryption | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |
| `ecdh_x25519.py` | Key establishment (ECDH path) | `X25519PrivateKey`/`X25519PublicKey` + `HKDF` (SHA-256) |
| `rsa_oaep_hybrid.py` | Key establishment (RSA path) | `rsa.generate_private_key` + OAEP padding (SHA-256, MGF1) |
| `signatures.py` | Non-repudiation (AUDIT+CRITICAL only) | `Ed25519PrivateKey`/`Ed25519PublicKey` |

No primitive is hand-rolled; all cryptographic operations delegate to the
`cryptography` library's audited implementations. No raw/textbook RSA,
no ECB mode, no custom KDF.

### ECDH/X25519 + HKDF Construction

```
1. Recipient has a long-term X25519 key pair.
2. Sender generates a FRESH EPHEMERAL X25519 key pair per message.
3. Both sides independently compute ECDH(their_private, other's_public)
   -> shared_secret (identical on both sides — this is the core ECDH
   property, verified by test_shared_key_matches_both_directions).
4. HKDF-SHA256(shared_secret, salt, info="sahe-v1-aes-key") -> 256-bit AES key.
5. Sender's ephemeral public key + salt + info are sent to the recipient
   as the `EcdhEncryptionContext` (safe to store/transmit — recovering
   the AES key from it requires the recipient's private key).
```

This is a standard ECIES-like flow, not an invented primitive, per the
Phase 0 correction. Using a fresh ephemeral key pair per message gives
forward secrecy: compromising one message's ephemeral key does not
expose other messages' keys.

### RSA-OAEP Hybrid

```
1. Generate a random AES-256 key.
2. AES-256-GCM encrypts the payload with that key.
3. RSA-OAEP (SHA-256, MGF1) wraps the AES key using the recipient's
   long-term RSA public key.
4. Store: AES-GCM ciphertext + nonce + RSA-wrapped key.
```

RSA key size: 3072 bits by default (`RSA_KEY_SIZE_BITS`), chosen for a
more future-proof security margin than the 2048-bit floor commonly seen
in older deployments — this increases RSA's already-higher computational
cost relative to ECDH, a trade-off made explicit in the Phase 7
benchmark comparison rather than hidden.

### Signature Policy (Narrow, Justified)

`_signature_required()` in `policy.py` returns `True` for exactly one
combination: `DataType.AUDIT` + `Severity.CRITICAL`. Verified by
`test_signature_not_required_for_high_severity_non_audit`, which
explicitly checks that CRITICAL severity alone (on an ALERT record) does
NOT trigger a signature, and that HIGH severity on an AUDIT record does
NOT either — only the exact AUDIT+CRITICAL combination does.

## SAHE Policy Engine (crypto/sahe/policy.py)

`decide(payload_size_bytes, severity, data_type, config)` returns a
`SaheDecision` with:
- which key-establishment method to use (ECDH_X25519 or RSA_OAEP)
- whether a signature is required, and why
- a human-readable rationale string

**Current threshold policy (PLACEHOLDER, pending Phase 8):**
- Below `large_payload_threshold_bytes` (default 1 MB): ECDH/X25519
- At or above: RSA-OAEP

This crossover point is a documented placeholder, not an experimentally
justified value — Phase 7 will produce real timing measurements across
payload sizes for both key-establishment methods, and Phase 8 will use
that data to either confirm or revise this threshold. The current
rationale for defaulting to ECDH below the threshold (forward secrecy,
smaller keys than RSA at equivalent security) is a reasonable starting
policy but is explicitly not claimed as empirically optimal yet.

## SAHE Engine (crypto/sahe/engine.py)

`encrypt_with_sahe()` / `decrypt_with_sahe()` execute a `SaheDecision`
using the real primitives above, producing/consuming a `SaheEnvelope`
(the shape that will be stored in MongoDB in Phase 10). This has been
verified with real round-trip encryption/decryption tests covering:
- the ECDH path
- the RSA path (triggered by an actual payload crossing the real default
  1 MB threshold, not a mocked threshold)
- the AUDIT+CRITICAL signature path, including tamper detection
- wrong-recipient rejection (a party without the correct private key
  cannot decrypt, on both the ECDH and RSA paths)

## Testing

49 tests across `tests/crypto/`:
- `test_aes_gcm.py` (11) — round-trip, tamper detection (ciphertext,
  nonce, associated data), wrong key, large (5MB) payload
- `test_ecdh_x25519.py` (8) — shared-secret agreement from both sides,
  full sender/recipient flow, wrong-key mismatch, HKDF salt/info
  sensitivity
- `test_rsa_oaep_hybrid.py` (6) — wrap/unwrap round-trip, full hybrid
  flow, wrong-key failure, PEM serialization
- `test_signatures.py` (6) — sign/verify round-trip, tampered
  message/signature detection, wrong-key rejection
- `test_sahe_policy.py` (11) — threshold behavior, the narrow signature
  policy (including the key regression test that HIGH/CRITICAL severity
  alone does NOT trigger a signature outside AUDIT+CRITICAL)
- `test_sahe_engine.py` (7) — full encrypt/decrypt round-trips on both
  key-establishment paths, signature path, tamper/wrong-recipient
  rejection

**These are real cryptographic operations run in this environment, not
synthetic-fixture stand-ins** — the only sense in which this differs
from "real-world" testing is that no actual CICIDS2017 log data was
encrypted (arbitrary byte strings were used as plaintext, which is
sufficient to validate correctness of the cryptography itself).

## How to Run

```bash
pip install cryptography

python -m pytest tests/crypto/ -v
```

## Limitations

- SAHE's size thresholds are placeholders pending Phase 8's
  experimentally-derived values.
- `RecipientKeys` in `engine.py` is the interface Phase 9's key manager
  must satisfy, but no actual key-management/storage system (KMS,
  encrypted local keystore) has been built yet — Phase 9 will need to
  decide how keys are actually persisted and rotated in the running
  system.
- HKDF `salt` is currently `None` by default in the ECDH path used
  inside `sender_establish_key()`; a real per-message salt (e.g. derived
  from the event ID) should be decided when this is wired into the
  Phase 9 backend, as noted in `ecdh_x25519.py`'s docstring.
- The RSA-vs-ECDH threshold policy's stated rationale (forward secrecy,
  smaller keys) is standard cryptographic reasoning but has not yet been
  validated against this specific system's actual measured performance
  characteristics — that validation is Phase 7/8's job.
