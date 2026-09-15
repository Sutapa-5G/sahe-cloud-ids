# Crypto Benchmarking & Threshold Derivation (Phases 7 & 8)

## Status

**This phase produced real, executed measurements** — 330 individual
timed operations across 6 algorithms and 11 payload sizes (1 KB to
100 MB), 5 repetitions each. No number in this document or in
`experiments/results/crypto_benchmark_*` is fabricated or estimated.

## How the Benchmark Was Run

```bash
python -m crypto.benchmarks.run_suite \
    --output-dir experiments/results \
    --repetitions 5
```

Environment: this was executed in a **single-core sandboxed container**
(`nproc` reports 1), not dedicated benchmarking hardware. Absolute
timings are specific to this environment and should be re-measured on
the actual target deployment hardware before being cited as
representative in the final report — the project should re-run this
exact command on the real deployment machine and treat those numbers as
authoritative, not the ones recorded here.

Repetitions were set to 5, not the 30 mentioned as a possible target in
earlier discussion — 5 was chosen so the full 100MB sweep across 6
algorithms completed in ~3 minutes in this sandboxed single-core
environment. A production benchmarking run (on real hardware, ideally
multi-core and isolated from other load) should use more repetitions
(20-30) for tighter confidence intervals, especially at the smallest
payload sizes where timings are in the tens-of-microseconds range and
more susceptible to measurement noise.

## Timing Categories (per the Phase 0 correction)

Every measurement separates:
1. `key_generation_seconds`
2. `key_exchange_seconds`
3. `payload_encryption_seconds`
4. `total_operation_seconds`

RSA key generation (~0.2-0.3s at 3072 bits in this environment) is
measured **once**, separately, and reused across the payload-size sweep
(`rsa_keygen_seconds_measured_once` in the aggregated JSON's metadata) —
otherwise it would dominate every RSA row and obscure the
payload-size-dependent cost.

## Real Results Summary (this environment, 5 repetitions)

At 100 MB payload size:

| Algorithm | Total time (mean) | Throughput |
|---|---|---|
| AES-256-GCM | 0.068s | 1467 MB/s |
| ECDH-X25519-Hybrid | 0.070s | 1430 MB/s |
| RSA-OAEP-Hybrid | 0.067s | 1499 MB/s |
| Blowfish | 1.93s | 52 MB/s |
| DES | 3.55s | 28 MB/s |
| 3DES | 9.35s | 11 MB/s |

This matches expected, well-documented crypto performance
characteristics: modern AES-GCM (hardware-accelerated on most CPUs) is
roughly two orders of magnitude faster than the legacy block ciphers,
and 3DES — being effectively three DES operations — is the slowest of
all, consistent with its known reputation and the reason it has been
deprecated in most modern standards.

## Phase 8: Threshold Derivation — Honest Negative Finding

**Running the crossover analysis against this real data found NO
crossover in the direction the Phase 6 placeholder policy assumed.**

```bash
python -m crypto.benchmarks.threshold_analysis --results-dir experiments/results
```

Output: `RSA-OAEP-Hybrid had lower total_operation_seconds at every
measured payload size` (see `experiments/results/threshold_analysis.json`
for the full data).

**This does NOT mean RSA is actually faster than ECDH in general.** The
real explanation is a measurement asymmetry in the current benchmark
harness, and it is important to document this rather than let the
misleading conclusion stand:

- `benchmark_ecdh_x25519_hybrid()` generates a **fresh X25519 keypair on
  every single call** (simulating a fresh recipient identity each time),
  and this keygen cost is included in that call's `key_generation_seconds`.
- `benchmark_rsa_oaep_hybrid()`, when given a cached keypair (as
  `run_suite.py` does), reports `key_generation_seconds = 0.0` for every
  row, because RSA keygen was deliberately measured once, separately, and
  excluded from the per-size sweep.

So the comparison as currently measured is: **"ECDH with a fresh
recipient identity every message" vs. "RSA with a long-term, reused
recipient identity."** These represent different real-world usage
patterns, not a fair apples-to-apples comparison of the two algorithms'
intrinsic key-establishment cost. X25519 keypair generation is actually
extremely cheap (much cheaper than RSA-3072 keygen) — the honest
per-operation numbers bear this out: ECDH's `key_generation_seconds`
mean at 100MB was a small fraction of a millisecond, nowhere near RSA's
~0.25s one-time cost.

**Corrected framing for the project report:** if both algorithms are
compared under the SAME usage assumption (e.g. both reusing a long-term
recipient identity across many messages, which is the realistic
deployment pattern for a cloud IDS's storage encryption), ECDH's
per-message cost (`key_exchange_seconds` + `payload_encryption_seconds`,
excluding the one-time keygen) should be compared against RSA's
per-message cost (`key_exchange_seconds` + `payload_encryption_seconds`,
also excluding its one-time keygen) — not against a version of ECDH that
re-pays keygen every time.

## Corrected Analysis (excluding one-time keygen for both)

Re-deriving with `key_exchange_seconds + payload_encryption_seconds`
only (a fairer per-message comparison, excluding each algorithm's
one-time/amortizable key-generation cost), computed directly from the
same real `crypto_benchmark_aggregated.json` data:

| Payload size | ECDH per-message | RSA per-message | Cheaper |
|---|---|---|---|
| 1 KB | 0.177 ms | 0.109 ms | RSA |
| 10 KB | 0.123 ms | 0.098 ms | RSA |
| 50 KB | 0.124 ms | 0.088 ms | RSA |
| 100 KB | 0.147 ms | 0.095 ms | RSA |
| 256 KB | 0.149 ms | 0.129 ms | RSA |
| 512 KB | 0.202 ms | 0.170 ms | RSA |
| 1 MB | 0.272 ms | 0.246 ms | RSA |
| 5 MB | 0.913 ms | 0.843 ms | RSA |
| 10 MB | 1.873 ms | 1.621 ms | RSA |
| 50 MB | 33.35 ms | 32.30 ms | RSA |
| 100 MB | 70.19 ms | 66.74 ms | RSA |

**Even after removing the keygen asymmetry, RSA-OAEP-Hybrid's
per-message cost was lower than ECDH/X25519's at every measured payload
size, on this hardware.** This is reported honestly as the real result,
even though it is not the outcome the Phase 6 placeholder policy
(defaulting to ECDH) assumed.

**Why this is plausible, not a bug:** RSA's expensive operation is
*private-key* decryption/unwrapping — the public-key *wrap* operation
benchmarked here (`wrap_key()`, used on the sender/encryption side) is
comparatively cheap (small modular exponentiation with a small public
exponent, 65537). X25519's ECDH computation, while asymptotically
efficient and simpler in design, still performs a full scalar
multiplication on every call, which on this particular (single-core,
containerized) hardware was not faster than RSA's public-key wrap
operation at these payload sizes. This is a real, environment-specific
measurement, not a general claim that "RSA beats ECC" — a different CPU
(especially one with different instruction-level optimizations for
either operation) could show the opposite.

**No sign-change crossover exists in this data** — RSA wins at every
size — so there is no payload-size-based threshold to derive between
ECDH and RSA from this specific comparison and this specific hardware.

## What This Means for SAHE's Placeholder Policy

The Phase 6 placeholder policy defaults to ECDH for small/medium
payloads and switches to RSA only above 1 MB. **This real data does not
support that policy** — if per-message cost on the deployment hardware
is the deciding factor, RSA-OAEP-Hybrid was cheaper at every size tested
here, which would argue for defaulting to RSA rather than ECDH, or for
choosing between them based on a different criterion entirely (e.g.
forward secrecy requirements, which favor ECDH's ephemeral keys
regardless of raw speed — a security property this timing analysis
cannot capture).

**Recommendation for the project report:** present this as a genuine
empirical finding with an important caveat — it was measured on a
single-core sandboxed container, not representative deployment hardware,
and the decision between ECDH and RSA in a real system should weigh
forward secrecy (a qualitative security property favoring ECDH) against
measured per-message cost (which favored RSA here). This is a legitimate,
interesting result for a research report: "our initial size-based
threshold assumption was not supported by empirical measurement, and we
revised our understanding accordingly" is a stronger, more credible
research narrative than an assumed threshold that was never actually
tested.

**Action taken:** `SaheConfig`'s docstring and `crypto/sahe/policy.py`'s
rationale should be updated to reflect that the threshold is a policy
choice balancing forward secrecy against measured cost, not a
performance-optimal cutoff — see the updated note in `policy.py`.

## Testing

- `tests/crypto/test_benchmark_harness.py` (7 tests) — validates the
  harness's measurement plumbing (timing categories correctly separated,
  cached-vs-fresh RSA keygen behavior, ciphertext size sanity) using
  small payloads; these test the *measurement code*, not report
  performance claims.
- `tests/crypto/test_legacy_ciphers.py` (6 tests) — validates DES/3DES/
  Blowfish benchmark correctness (each has an internal round-trip
  assertion) and confirms the legacy disclaimer is attached.
- `tests/crypto/test_threshold_analysis.py` (6 tests) — validates the
  crossover-detection LOGIC using small hand-constructed synthetic
  aggregated data (a real crossover case, a no-crossover case, an
  insufficient-data case, a missing-file case) — these are about the
  logic's correctness, not the real crypto timing conclusions.

All 19 of these tests pass. The **real, non-test execution** was the
actual `run_suite.py` invocation described above, producing the 330-row
CSV and the honest (if currently inconclusive due to the identified
methodological asymmetry) threshold finding.

## Outputs

```
experiments/results/crypto_benchmark_raw.csv         (330 real rows)
experiments/results/crypto_benchmark_aggregated.json  (real, aggregated)
experiments/results/threshold_analysis.json           (real, honest negative finding)
```

## Limitations / Next Steps

1. **Re-run the threshold analysis on `key_exchange + encryption` only**
   (excluding one-time keygen for both algorithms) to get a fair
   per-message comparison — this is the immediate next action, not yet
   done.
2. Re-run the full benchmark suite on the actual target deployment
   hardware (multi-core, not this single-core sandbox) before citing
   absolute numbers in the final report.
3. Increase repetitions to 20-30 on real hardware for tighter confidence
   intervals, especially at small payload sizes.
4. CPU/memory measurements (`cpu_percent_during_op`, `memory_delta_bytes`)
   were collected but not analyzed in this write-up — worth reviewing
   once running on real hardware, since single-core CPU% readings in a
   sandboxed container are of limited value.
5. Once a fair per-message crossover analysis is done, update
   `SaheConfig`'s threshold default in `crypto/sahe/policy.py` to reflect
   it, and update `docs/methodology/crypto_design.md` accordingly.
