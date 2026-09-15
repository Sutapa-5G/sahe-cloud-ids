import asyncio


def test_websocket_connects(client):
    with client.websocket_connect("/ws/events") as websocket:
        # Connection succeeded if we get here without raising.
        pass


def test_websocket_manager_broadcast_reaches_connected_client():
    """
    Tests the ConnectionManager directly (not through the HTTP test
    client, which doesn't easily let us trigger a server-side broadcast
    mid-connection) — verifies the broadcast/disconnect-cleanup logic.
    """
    from backend.app.websocket.manager import ConnectionManager

    manager = ConnectionManager()
    assert manager.active_connection_count == 0

    class FakeWebSocket:
        def __init__(self):
            self.sent = []
            self.accepted = False

        async def accept(self):
            self.accepted = True

        async def send_text(self, text):
            self.sent.append(text)

    async def run():
        ws1 = FakeWebSocket()
        ws2 = FakeWebSocket()
        await manager.connect(ws1)
        await manager.connect(ws2)
        assert manager.active_connection_count == 2

        await manager.broadcast({"event": "test_alert", "severity": "HIGH"})
        assert len(ws1.sent) == 1
        assert len(ws2.sent) == 1
        assert "test_alert" in ws1.sent[0]

    asyncio.run(run())


def test_websocket_manager_removes_stale_connection_on_send_failure():
    from backend.app.websocket.manager import ConnectionManager

    manager = ConnectionManager()

    class WorkingWebSocket:
        def __init__(self):
            self.sent = []

        async def accept(self):
            pass

        async def send_text(self, text):
            self.sent.append(text)

    class BrokenWebSocket:
        async def accept(self):
            pass

        async def send_text(self, text):
            raise ConnectionError("simulated dead connection")

    async def run():
        good = WorkingWebSocket()
        bad = BrokenWebSocket()
        await manager.connect(good)
        await manager.connect(bad)
        assert manager.active_connection_count == 2

        await manager.broadcast({"event": "test"})
        # The broken connection should have been dropped, the working one kept.
        assert manager.active_connection_count == 1
        assert len(good.sent) == 1

    asyncio.run(run())
