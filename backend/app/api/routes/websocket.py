"""
backend/app/api/routes/websocket.py

/ws/events — clients connect here to receive live alert broadcasts.
"""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.websocket.manager import manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            # This endpoint is broadcast-only from the server's
            # perspective; it still needs to await something to detect
            # disconnects. Any message a client sends is currently
            # ignored (no client-to-server protocol defined yet).
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
