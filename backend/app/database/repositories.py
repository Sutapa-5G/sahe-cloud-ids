"""
backend/app/database/repositories.py

Repository pattern: one class per collection, encapsulating queries so
route/service code never constructs raw Mongo queries directly. Each
repository is constructed with a database-like object exposing the
motor/pymongo async collection interface (works identically against a
real motor database or a mongomock-backed one wrapped for async use -
see backend/tests/database/conftest.py for how tests provide this).
"""
from __future__ import annotations

from backend.app.database.models import (
    EventDocument,
    BenchmarkResultDocument,
    FirewallActionDocument,
    AuditLogDocument,
)


class EventRepository:
    def __init__(self, db):
        self._collection = db["events"]

    async def insert(self, event: EventDocument) -> None:
        await self._collection.insert_one(event.model_dump())

    async def get_by_id(self, event_id: str) -> EventDocument | None:
        doc = await self._collection.find_one({"event_id": event_id})
        if doc is None:
            return None
        doc.pop("_id", None)
        return EventDocument(**doc)

    async def list_all(self, limit: int = 100) -> list[EventDocument]:
        cursor = self._collection.find().sort("timestamp", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        for d in docs:
            d.pop("_id", None)
        return [EventDocument(**d) for d in docs]

    async def list_by_severity(self, severity: str, limit: int = 100) -> list[EventDocument]:
        cursor = self._collection.find({"severity": severity}).sort("timestamp", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        for d in docs:
            d.pop("_id", None)
        return [EventDocument(**d) for d in docs]

    async def count_by_attack_type(self) -> dict[str, int]:
        pipeline = [{"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}]
        results = await self._collection.aggregate(pipeline).to_list(length=None)
        return {r["_id"]: r["count"] for r in results}


class BenchmarkResultRepository:
    def __init__(self, db):
        self._collection = db["benchmark_results"]

    async def insert_many(self, results: list[BenchmarkResultDocument]) -> None:
        if not results:
            return
        await self._collection.insert_many([r.model_dump() for r in results])

    async def get_by_algorithm(self, algorithm: str) -> list[BenchmarkResultDocument]:
        cursor = self._collection.find({"algorithm": algorithm}).sort("payload_size_bytes", 1)
        docs = await cursor.to_list(length=None)
        for d in docs:
            d.pop("_id", None)
        return [BenchmarkResultDocument(**d) for d in docs]

    async def get_all(self) -> list[BenchmarkResultDocument]:
        cursor = self._collection.find().sort([("algorithm", 1), ("payload_size_bytes", 1)])
        docs = await cursor.to_list(length=None)
        for d in docs:
            d.pop("_id", None)
        return [BenchmarkResultDocument(**d) for d in docs]


class FirewallActionRepository:
    def __init__(self, db):
        self._collection = db["firewall_actions"]

    async def insert(self, action: FirewallActionDocument) -> None:
        await self._collection.insert_one(action.model_dump())

    async def list_by_ip(self, ip: str) -> list[FirewallActionDocument]:
        cursor = self._collection.find({"ip": ip}).sort("timestamp", 1)
        docs = await cursor.to_list(length=None)
        for d in docs:
            d.pop("_id", None)
        return [FirewallActionDocument(**d) for d in docs]

    async def list_recent(self, limit: int = 50) -> list[FirewallActionDocument]:
        cursor = self._collection.find().sort("timestamp", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        for d in docs:
            d.pop("_id", None)
        return [FirewallActionDocument(**d) for d in docs]


class AuditLogRepository:
    """
    Append-only by design: no update/delete method is exposed, matching
    the audit log's requirement (see backend/app/audit/audit_logger.py's
    docstring and the Phase 0 review's audit-logging requirement).
    """
    def __init__(self, db):
        self._collection = db["audit_log"]

    async def insert(self, entry: AuditLogDocument) -> None:
        await self._collection.insert_one(entry.model_dump())

    async def list_by_correlation_id(self, correlation_id: str) -> list[AuditLogDocument]:
        cursor = self._collection.find({"correlation_id": correlation_id}).sort("timestamp", 1)
        docs = await cursor.to_list(length=None)
        for d in docs:
            d.pop("_id", None)
        return [AuditLogDocument(**d) for d in docs]

    async def list_recent(self, limit: int = 100) -> list[AuditLogDocument]:
        cursor = self._collection.find().sort("timestamp", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        for d in docs:
            d.pop("_id", None)
        return [AuditLogDocument(**d) for d in docs]
