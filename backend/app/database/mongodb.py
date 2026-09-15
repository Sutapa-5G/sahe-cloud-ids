"""
backend/app/database/mongodb.py

MongoDB connection management and index setup, per the schema defined in
docs/architecture/overview.md (events, crypto_metadata, benchmark_results,
firewall_actions, audit_log collections).

IMPORTANT - environment limitation: no real MongoDB server is reachable
in the development sandbox this project was built in (no `mongod`
binary, port 27017 unreachable, and the sandbox's network access is
restricted to package registries, not general server processes). This
module's actual database I/O has been tested ONLY against `mongomock`
(a library that simulates MongoDB's real query/index/CRUD behavior
in-memory for testing) - never against a real `mongod` instance. This is
a genuine gap, not a hidden one: docs/methodology/mongodb.md documents
it explicitly, and the connection code here is written to work
identically against a real MongoDB (motor/pymongo's API is what
mongomock mimics), but the user must run this against a real MongoDB
locally and confirm it before treating it as verified.
"""
from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase


class MongoManager:
    """
    Thin wrapper around an AsyncIOMotorClient/Database, so application
    code depends on this class (easy to substitute a mongomock-backed
    instance in tests) rather than importing motor directly everywhere.
    """

    def __init__(self, uri: str, db_name: str):
        self.uri = uri
        self.db_name = db_name
        self._client: AsyncIOMotorClient | None = None
        self._db: AsyncIOMotorDatabase | None = None

    def connect(self, server_selection_timeout_ms: int = 500) -> None:
        """
        server_selection_timeout_ms defaults to a SHORT 500ms rather
        than motor/pymongo's default (30s). This matters a lot for this
        project: in an environment where MongoDB may genuinely be
        unavailable (as in the development sandbox this was built in),
        a long default timeout makes every app startup and every test
        that creates a fresh app instance slow — with dozens of tests
        each creating their own app instance, even a few seconds each
        adds up to minutes. A real production deployment with a
        reliably-present MongoDB can pass a larger value if needed
        (e.g. if network latency to a remote MongoDB cluster exceeds
        500ms under normal conditions).
        """
        self._client = AsyncIOMotorClient(
            self.uri, serverSelectionTimeoutMS=server_selection_timeout_ms
        )
        self._db = self._client[self.db_name]

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
            self._db = None

    @property
    def db(self) -> AsyncIOMotorDatabase:
        if self._db is None:
            raise RuntimeError("MongoManager.connect() must be called before accessing .db")
        return self._db

    async def ensure_indexes(self) -> None:
        """
        Creates the indexes specified in docs/architecture/overview.md.
        Safe to call repeatedly (create_index is idempotent for an
        identical index spec).
        """
        events = self.db["events"]
        await events.create_index("timestamp")
        await events.create_index("severity")
        await events.create_index("attack_type")
        await events.create_index("event_id", unique=True)

        crypto_metadata = self.db["crypto_metadata"]
        await crypto_metadata.create_index("event_id")

        benchmark_results = self.db["benchmark_results"]
        await benchmark_results.create_index("algorithm")
        await benchmark_results.create_index("payload_size_bytes")

        firewall_actions = self.db["firewall_actions"]
        await firewall_actions.create_index("ip")
        await firewall_actions.create_index("timestamp")

        audit_log = self.db["audit_log"]
        await audit_log.create_index("timestamp")
        await audit_log.create_index("event_type")
        await audit_log.create_index("correlation_id")
