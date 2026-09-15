"""
backend/app/websocket/manager.py

Manages connected WebSocket clients and broadcasts alert events to all
of them. Redis is deliberately NOT used here — per the original project
scope, Redis is optional/deferred and this in-process manager is
sufficient for a single-backend-instance deployment (the realistic scale
for this final-year project).
"""
from __future__ import annotations

import json
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._active_connections:
            self._active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        """
        Sends `message` (JSON-serialized) to every connected client.
        A client whose send fails (e.g. it disconnected without a clean
        close) is removed from the active list rather than letting one
        bad connection break the broadcast to everyone else.
        """
        payload = json.dumps(message, default=str)
        stale: list[WebSocket] = []
        for connection in self._active_connections:
            try:
                await connection.send_text(payload)
            except Exception:  # noqa: BLE001 - a dead connection must not break broadcast to others
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)

    @property
    def active_connection_count(self) -> int:
        return len(self._active_connections)


# Module-level singleton — a FastAPI app typically wants exactly one
# connection manager shared across all WebSocket routes/handlers.
manager = ConnectionManager()
