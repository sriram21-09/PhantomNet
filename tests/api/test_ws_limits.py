import os
import sys
import pytest
import asyncio
from unittest.mock import MagicMock

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.api.realtime import RealTimeManager, MAX_CONNECTIONS_PER_USER, MAX_CONNECTIONS_PER_IP


@pytest.mark.anyio
async def test_per_user_connection_limits():
    """
    RT-03: Max 5 concurrent connections per user.
    6th concurrent connection must be rejected.
    """
    mgr = RealTimeManager()
    user_id = "analyst_alice"
    ip = "192.168.1.50"

    mock_sockets = [MagicMock() for _ in range(5)]
    for ws in mock_sockets:
        allowed, reason = await mgr.can_connect(user_id, ip)
        assert allowed is True
        await mgr.register(ws, user_id, ip)

    # 6th connection attempt must be denied
    allowed_6th, reason = await mgr.can_connect(user_id, ip)
    assert allowed_6th is False
    assert "user exceeded" in reason

    # After closing one socket, connection is permitted again
    await mgr.unregister(mock_sockets[0])
    allowed_after, _ = await mgr.can_connect(user_id, ip)
    assert allowed_after is True


@pytest.mark.anyio
async def test_per_ip_connection_limits():
    """
    RT-03: Max 20 concurrent connections per IP address.
    21st connection from the same IP must be rejected.
    """
    mgr = RealTimeManager()
    ip = "10.0.5.99"

    mock_sockets = [MagicMock() for _ in range(20)]
    for idx, ws in enumerate(mock_sockets):
        user_id = f"user_{idx}"
        allowed, _ = await mgr.can_connect(user_id, ip)
        assert allowed is True
        await mgr.register(ws, user_id, ip)

    # 21st connection attempt from same IP must be denied
    allowed_21st, reason = await mgr.can_connect("user_21", ip)
    assert allowed_21st is False
    assert "IP exceeded" in reason
