"""Tests for WebSocket ConnectionManager broadcasting and channel management."""

from unittest.mock import AsyncMock

import pytest

from websocket.manager import ConnectionManager


@pytest.mark.asyncio
async def test_websocket_connect_and_broadcast():
    """ConnectionManager connects client, broadcasts payload, and cleans up on disconnect."""
    manager = ConnectionManager()
    mock_ws = AsyncMock()
    mock_ws.accept = AsyncMock()
    mock_ws.send_text = AsyncMock()

    # 1. Connect
    await manager.connect(mock_ws, "events")
    assert manager.connection_count == 1

    # 2. Broadcast
    payload = {"type": "alert", "title": "Test Alert", "severity": "high"}
    await manager.broadcast("events", payload)
    assert mock_ws.send_text.called
    sent_text = mock_ws.send_text.call_args[0][0]
    assert "Test Alert" in sent_text
    assert "events" in sent_text

    # 3. Disconnect
    await manager.disconnect(mock_ws, "events")
    assert manager.connection_count == 0


@pytest.mark.asyncio
async def test_websocket_dead_client_cleanup():
    """Dead or broken WebSockets are automatically disconnected on broadcast failure."""
    manager = ConnectionManager()
    bad_ws = AsyncMock()
    bad_ws.accept = AsyncMock()
    bad_ws.send_text = AsyncMock(side_effect=RuntimeError("Socket closed"))

    await manager.connect(bad_ws, "alerts")
    assert manager.connection_count == 1

    # Broadcast will catch exception and disconnect
    await manager.broadcast("alerts", {"msg": "hello"})
    assert manager.connection_count == 0
