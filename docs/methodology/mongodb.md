# MongoDB Integration Methodology (Phase 10)

## Status

Implemented and tested - 20 new tests, all passing. **Critical
limitation, stated plainly: no real MongoDB server was reachable in the
development sandbox this project was built in** (no `mongod` binary, TCP
port 27017 connection refused, and the sandbox's network access is
restricted to package registries - it cannot install or run a database
server process). Every database test in this phase runs against
`mongomock`, a library that simulates MongoDB's real query/CRUD/index
behavior in-memory. This is a well-regarded, widely-used testing tool -
but it is still a simulator, not real MongoDB, and this document says so
throughout rather than blurring the line.

## What "Real" Means Here, Precisely

| Claim | Verified how |
|---|---|
| Repository query logic (filters, sorts, limits, aggregation) is correct | Real code, executed against mongomock - genuinely exercises the actual `repositories.py` code, just against a simulator |
| The app's real MongoDB connection code path (`MongoManager.connect()`, `ensure_indexes()`) doesn't have typos/syntax errors | Verified indirectly: the same method calls were tested against mongomock, and the app was verified to attempt a REAL connection to `localhost:27017` and correctly detect and report its absence |
| The app gracefully falls back to in-memory storage when MongoDB is unreachable | Genuinely verified for real - this is not simulated, the app actually tried to connect to a real (absent) MongoDB and its fallback logic actually ran |
| Real MongoDB's actual behavior (replica sets, real network partitions, real index performance at scale, auth, TLS) | NOT verified. This requires a real MongoDB instance, which the user must set up and test against before trusting this in production. |

## What Was Built

```
backend/app/database/
├── mongodb.py          - MongoManager: connection + ensure_indexes()
├── models.py            - Pydantic documents: EventDocument, BenchmarkResultDocument,
│                           FirewallActionDocument, AuditLogDocument
└── repositories.py      - EventRepository, BenchmarkResultRepository,
                            FirewallActionRepository, AuditLogRepository
```

Plus, in `backend/tests/database/mongomock_async_wrapper.py`, a small
test-only async wrapper around mongomock's synchronous API (mongomock
has no native async support as of the version used here), implementing
just the subset of motor's interface this project's repositories need
(`find`, `find_one`, `insert_one`, `insert_many`, `aggregate`,
`create_index`, cursor `sort`/`limit`/`to_list`). This lets the exact
same repository code run against mongomock in tests and real motor in
production without any repository code changes.

## Schema (per docs/architecture/overview.md)

| Collection | Document model | Indexes |
|---|---|---|
| `events` | `EventDocument` | `timestamp`, `severity`, `attack_type`, `event_id` (unique) |
| `crypto_metadata` | (embedded in `EventDocument.crypto`, separate collection index reserved for future denormalized queries) | `event_id` |
| `benchmark_results` | `BenchmarkResultDocument` | `algorithm`, `payload_size_bytes` |
| `firewall_actions` | `FirewallActionDocument` | `ip`, `timestamp` |
| `audit_log` | `AuditLogDocument` | `timestamp`, `event_type`, `correlation_id` |

`AuditLogRepository` deliberately exposes no update/delete method -
verified by `test_audit_log_has_no_update_or_delete_methods` - matching
the Phase 0 review's append-only audit-log requirement.

## Graceful Fallback Design

`backend/app/main.py`'s `lifespan()` now:
1. Attempts a real MongoDB connection (`MongoManager.connect()` plus
   an actual `ping` command - not just constructing the client object,
   which is lazy and wouldn't itself reveal a connection failure).
2. On success: runs `ensure_indexes()`, sets
   `app.state.event_repository` to a real `EventRepository`.
3. On failure (the current state in this sandbox): logs a clear message,
   closes the failed client, and sets `app.state.event_repository = None`.

`/events` routes (`api/routes/events.py`) check
`app.state.event_repository`: if set, they use MongoDB; if `None`, they
use the original in-memory dict. Every API response includes a
`storage_backend` field (`"mongodb"` or `"in_memory_fallback"`) so a
caller - or a test - can always tell which mode served the request,
rather than the difference being silently invisible.

This was verified two ways in this session:
1. Running the real app with no MongoDB available: confirmed the
   fallback message logs, confirmed `storage_backend: "in_memory_fallback"`
   in the actual HTTP response.
2. Manually injecting a mongomock-backed `EventRepository` into a running
   app's `app.state`: confirmed `storage_backend: "mongodb"` and correct
   create/get/list behavior through the real HTTP API.

## A Real Bug Found and Fixed This Phase

The initial `MongoManager.connect()` used motor's default connection
timeout (30 seconds). Since this sandbox has no real MongoDB, EVERY test
that instantiated a fresh FastAPI app (most of `backend/tests/`) was
silently paying this cost during the lifespan startup - the full backend
test suite took 3.5 minutes to run 61 tests before this was caught and
fixed. Reduced `serverSelectionTimeoutMS` to 500ms (configurable),
bringing the same suite down to about 21 seconds. This is exactly the
kind of performance bug that's easy to miss when running one test at a
time but becomes obvious at scale - the same pattern that produced the
earlier ROC-AUC and Severity-enum bugs in this project: something looked
right until actually exercised broadly.

## How to Actually Verify This Against Real MongoDB

The user should do this before relying on Phase 10 in the final report:

```bash
# 1. Install and start a real MongoDB (not possible in the assistant's sandbox)
#    e.g. via Docker: docker run -d -p 27017:27017 mongo:7

# 2. Set MONGODB_URI in .env if not the default localhost:27017

# 3. Start the backend and confirm the log says "MongoDB connection established"
uvicorn backend.app.main:app --reload

# 4. Confirm /events responses show "storage_backend": "mongodb"
curl -X POST http://localhost:8000/events -H "Content-Type: application/json" \
     -d '{"attack_type": "DDoS", "severity": "HIGH"}'
```

## Testing

20 new tests:
- `test_event_repository.py` (7) - insert/get/list/filter/aggregate,
  correct `_id` stripping
- `test_other_repositories.py` (8) - benchmark, firewall action, audit
  log repositories, including the append-only structural check
- `test_index_specs.py` (1) - confirms all index specs are syntactically
  valid against a MongoDB-compatible interface
- `test_events_with_mongo.py` (4) - full HTTP-API-level tests with a
  mongomock-backed repository injected, proving the MongoDB code path
  works end-to-end through real requests

Plus the existing `test_events_routes.py` (3, unchanged) continues to
test the in-memory fallback path, which is the actual behavior in this
sandboxed checkout.

Run with:
```bash
python -m pytest backend/tests/database/ backend/tests/test_events_with_mongo.py backend/tests/test_events_routes.py -v
```

## Limitations

- No real MongoDB verification - the single most important caveat of
  this phase. Everything above is real code, real query logic, verified
  against a real simulator, but the actual database has never been
  touched.
- Only `/events` was wired to the fallback pattern in this phase. The
  crypto envelope store (`/encrypt`/`/decrypt`, still in-memory in
  `api/routes/crypto.py`) and the audit logger (still
  `InMemoryAuditSink` in `main.py`) were NOT migrated to MongoDB in this
  phase - they still use their Phase 9 in-memory placeholders.
  `MongoAuditSink` and a Mongo-backed crypto envelope store are natural
  next steps, following the exact same graceful-fallback pattern
  established here for `/events`.
- `mongomock`'s aggregation pipeline support, while good, is not 100%
  feature-complete relative to real MongoDB - `count_by_attack_type()`'s
  simple `$group` pipeline was tested and works, but more complex
  aggregations should be re-verified against real MongoDB before relying
  on them.
- The 500ms connection timeout is aggressive - appropriate for fast
  local-network MongoDB or Docker-Compose setups (Phase 15), but should
  be increased for any deployment where MongoDB is genuinely more than
  500ms away (e.g. certain cloud-hosted MongoDB Atlas configurations).
