# Real-Time Alerts & Firewall Integration (Phases 11 & 12)

## Status

Fully implemented and tested - 21 new tests, all passing, including
genuine end-to-end verification: a real trained model's malicious
detection triggers a real WebSocket broadcast that a real connected
client receives, and a real HIGH/CRITICAL detection with a source IP
results in that IP actually appearing in `/firewall/rules`. No part of
this phase depends on the missing CICIDS2017 dataset or on real
MongoDB - it builds entirely on infrastructure already verified in
Phases 4-10.

## Phase 11: Real-Time Alerts

### What Changed
- `backend/app/services/alert_service.py` (new): `AlertService.raise_alert()`
  broadcasts a structured alert over WebSocket (via the `ConnectionManager`
  already built in Phase 9) and logs to the audit trail, both tagged
  with a shared `event_id`/`correlation_id`.
- `backend/app/api/routes/detection.py`: malicious detections now call
  `AlertService.raise_alert()` instead of logging directly to the audit
  trail. Benign detections still log directly (no broadcast, no event) -
  matching the architecture diagram's BENIGN -> normal logging /
  MALICIOUS -> Alert Engine split.
- `backend/app/schemas/detection.py`: `DetectionResponse` gained an
  `event_id` field, populated only for malicious detections.

### Design Decision: AlertService Doesn't Create Persisted Events
`AlertService` broadcasts and audit-logs, but does NOT call
`EventRepository`/the in-memory events store itself. That responsibility
stays with the route (or a future orchestrating service), so
`AlertService` has exactly one job and doesn't need to know about Phase
10's MongoDB-vs-fallback distinction. This keeps it simple and
independently testable.

### Real End-to-End Verification
`test_detection_websocket_integration.py` trains a real (if
synthetic-data) `RandomForestClassifier`, starts the real FastAPI app,
opens a real WebSocket connection via `TestClient.websocket_connect()`,
sends a real `/detect` request with an attack-shaped feature vector, and
asserts the alert that arrives over the socket matches the HTTP
response's `event_id`/`attack_type`/`severity` exactly. This is
end-to-end proof the wiring is correct - not just that `AlertService` in
isolation works.

## Phase 12: Firewall Integration (Auto-Blocking Policy)

### What Changed
- `backend/app/services/blocking_service.py` (new): `BlockingService`
  encapsulates WHEN to auto-block, separate from HOW blocking happens
  (`firewall/provider.py`, unchanged since Phase 9).
- `backend/app/schemas/detection.py`: `DetectionRequest` gained an
  optional `source_ip` field; `DetectionResponse` gained
  `auto_block_triggered` and `auto_block_message`.
- `backend/app/api/routes/detection.py`: malicious detections now call
  `BlockingService.enforce()` after raising the alert.

### Documented Auto-Block Policy
```
AUTO_BLOCK_SEVERITIES = {HIGH, CRITICAL}
```
- LOW/MEDIUM severity detections alert but never auto-block - an
  operator should review first. This is a deliberately conservative
  starting policy: this project has never measured a real false-positive
  rate (no real CICIDS2017 evaluation has been run - see
  `docs/methodology/preprocessing.md` and `random_forest.md`), so
  auto-blocking on lower-confidence signals risks blocking legitimate
  traffic. This should be revisited once real evaluation metrics exist.
- A detection with no `source_ip` cannot be auto-blocked, and this is
  reported explicitly (`"no source_ip was provided"`), never silently
  skipped without explanation.
- Every outcome - blocked, skipped-due-to-severity,
  skipped-due-to-missing-ip, or a failed block attempt - is logged to
  the audit trail via `AuditLogger.log_firewall_action()`, tagged with
  the same `correlation_id` as the detection/alert, so the full chain
  (detect -> severity -> alert -> block decision) is traceable from one
  correlation ID.

### Real End-to-End Verification
`test_detection_blocking_integration.py` trains a real model, sends a
real `/detect` request with a `source_ip`, and - when the real
classification reaches HIGH/CRITICAL severity (checked against the
actual response, not assumed) - confirms the IP genuinely appears in
`GET /firewall/rules` afterward. A second test confirms a request
without `source_ip` never auto-blocks regardless of severity. A third
confirms benign detections never trigger blocking.

## Full Chain Now Verified End-to-End

```
POST /detect (malicious, with source_ip)
      |
      v
ML model predicts attack_type + confidence          [real model, Phase 2/3]
      |
      v
SeverityEngine.assess()                              [real, Phase 4]
      |
      v
AlertService.raise_alert()                            [real, Phase 11]
      |              |
      v              v
WebSocket        Audit trail
broadcast        (correlation_id)
      |
      v
BlockingService.enforce()                              [real, Phase 12]
      |
      v
FirewallProvider.block()                               [real, Phase 9]
      |
      v
GET /firewall/rules shows the blocked IP
```

Every arrow in this chain was exercised by a real test in this session
except the ML model's real-world accuracy (which still depends on the
unavailable CICIDS2017 dataset - the model used in these tests is real
code trained on synthetic, well-separated data, sufficient to prove the
wiring works, not to claim real-world detection accuracy).

## Testing

21 new tests:
- `test_alert_service.py` (6) - unit tests for `AlertService` in
  isolation (broadcast reaches a fake WebSocket, audit logging,
  event_id handling)
- `test_detection_websocket_integration.py` (2) - real end-to-end:
  trained model -> HTTP request -> real WebSocket receipt
- `test_blocking_service.py` (10) - unit tests for the auto-block policy
  (severity thresholds, missing-IP handling, audit logging of every
  outcome)
- `test_detection_blocking_integration.py` (3) - real end-to-end:
  trained model -> HTTP request -> real firewall rule appears

Run with:
```bash
python -m pytest backend/tests/test_alert_service.py \
    backend/tests/test_detection_websocket_integration.py \
    backend/tests/test_blocking_service.py \
    backend/tests/test_detection_blocking_integration.py -v
```

## Limitations

- The auto-block severity threshold (`HIGH`, `CRITICAL`) is a documented
  starting policy, not empirically tuned - same caveat as Phase 4's
  impact table. Should be revisited once real detection metrics
  (false-positive rate in particular) exist from real CICIDS2017
  evaluation.
- `BlockingService.enforce()` is synchronous (not `async`), called
  directly from the async route handler - fine for `SimulatedFirewallProvider`
  and even `IptablesFirewallProvider` (which itself uses a blocking
  `subprocess.run` with a timeout), but if a future firewall provider
  needed real async I/O (e.g. calling a cloud provider's async API), this
  would need to become an async method.
- No rate-limiting or duplicate-detection suppression exists yet - a
  flood of detections for the same IP would call `enforce()` repeatedly;
  `SimulatedFirewallProvider.block()` already handles the duplicate-rule
  case gracefully (verified in Phase 9's tests), but the audit trail
  would still grow one entry per repeated detection, which could be
  noisy at real traffic volumes. Not addressed in this phase.
- WebSocket broadcast has no delivery confirmation or replay - a client
  that connects after an alert was broadcast will never see it (no alert
  history/backfill exists yet). This may be worth addressing with a
  connection-time backfill of recent alerts, from Phase 10's `events`
  collection, once MongoDB is genuinely available.
