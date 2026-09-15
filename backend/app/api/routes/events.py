"""
backend/app/api/routes/events.py

GET/POST /events. Uses MongoDB (via EventRepository) when
app.state.event_repository is configured (real MongoDB or mongomock);
falls back to an in-memory dict otherwise. The fallback exists because
no real MongoDB server is available in the development sandbox this
project was built in — see docs/methodology/mongodb.md. The response
includes a `storage_backend` field so callers can always tell which mode
served the request, rather than silently masking the difference.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from backend.app.database.models import EventDocument, CryptoMetadata


router = APIRouter(prefix="/events", tags=["events"])

# In-memory fallback store, used only when no event_repository is
# configured on app.state (i.e. no MongoDB/mongomock available).
_events_store: dict[str, dict] = {}


class EventCreateRequest(BaseModel):
    attack_type: str
    severity: str
    envelope_id: str | None = None


class EventResponse(BaseModel):
    event_id: str
    attack_type: str
    severity: str
    envelope_id: str | None
    created_at: str
    storage_backend: str  # "mongodb" | "in_memory_fallback"


@router.post("", response_model=EventResponse)
async def create_event(body: EventCreateRequest, request: Request) -> EventResponse:
    event_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    repo = getattr(request.app.state, "event_repository", None)
    audit_logger = request.app.state.audit_logger

    if repo is not None:
        doc = EventDocument(
            event_id=event_id,
            timestamp=created_at,
            attack_type=body.attack_type,
            severity=body.severity,
            crypto=CryptoMetadata(scheme="none", key_management="none"),
            payload_base64="",
            nonce_base64="",
        )
        await repo.insert(doc)
        backend_used = "mongodb"
        audit_logger.log_storage(event_id, collection="events (MongoDB)")
    else:
        _events_store[event_id] = {
            "event_id": event_id, "attack_type": body.attack_type,
            "severity": body.severity, "envelope_id": body.envelope_id,
            "created_at": created_at,
        }
        backend_used = "in_memory_fallback"
        audit_logger.log_storage(event_id, collection="events (in-memory fallback — no MongoDB configured)")

    return EventResponse(
        event_id=event_id, attack_type=body.attack_type, severity=body.severity,
        envelope_id=body.envelope_id, created_at=created_at, storage_backend=backend_used,
    )


@router.get("", response_model=list[EventResponse])
async def list_events(request: Request) -> list[EventResponse]:
    repo = getattr(request.app.state, "event_repository", None)
    if repo is not None:
        docs = await repo.list_all()
        return [
            EventResponse(
                event_id=d.event_id, attack_type=d.attack_type, severity=d.severity,
                envelope_id=None, created_at=d.timestamp, storage_backend="mongodb",
            )
            for d in docs
        ]
    return [EventResponse(**e, storage_backend="in_memory_fallback") for e in _events_store.values()]


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(event_id: str, request: Request) -> EventResponse:
    repo = getattr(request.app.state, "event_repository", None)
    if repo is not None:
        doc = await repo.get_by_id(event_id)
        if doc is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No event found for id {event_id}.")
        return EventResponse(
            event_id=doc.event_id, attack_type=doc.attack_type, severity=doc.severity,
            envelope_id=None, created_at=doc.timestamp, storage_backend="mongodb",
        )

    event = _events_store.get(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No event found for id {event_id}.")
    return EventResponse(**event, storage_backend="in_memory_fallback")
