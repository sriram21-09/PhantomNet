import os
import sys
import time
import asyncio
import numpy as np
import pytest
from unittest.mock import AsyncMock, MagicMock

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.api.realtime import RealTimeManager


@pytest.mark.anyio
async def test_realtime_broadcast_200_clients_slo():
    """
    PERF-02: 200 concurrent connected clients:
    Broadcast delivery p95 latency must be <= 500 ms.
    """
    mgr = RealTimeManager()
    num_clients = 200
    latencies = []

    mock_sockets = []
    for i in range(num_clients):
        ws = MagicMock()
        
        async def make_send(client_idx):
            async def _send_text(msg):
                # simulate realistic network dispatch per client (0-2ms)
                await asyncio.sleep(0.001)
                latencies.append(time.perf_counter())
            return _send_text

        ws.send_text = AsyncMock(side_effect=await make_send(i))
        mock_sockets.append(ws)
        await mgr.register(ws, user_id=f"analyst_{i}", client_ip=f"10.0.0.{i % 15}")

    assert len(mgr.active_connections) == 200

    payload = {
        "event_id": "018f6c3a-9921-7000-8000-000000000999",
        "threat_score": 92.5,
        "threat_level": "CRITICAL",
        "attack_type": "SSH_BRUTE_FORCE",
        "src_ip": "203.0.113.55",
    }

    t0 = time.perf_counter()
    delivered = await mgr.broadcast("THREAT_ALERT", payload)
    total_broadcast_time_sec = time.perf_counter() - t0

    assert delivered == 200
    assert len(latencies) == 200

    delivery_durations = np.array(latencies) - t0
    p50_ms = np.percentile(delivery_durations, 50) * 1000
    p95_ms = np.percentile(delivery_durations, 95) * 1000
    p99_ms = np.percentile(delivery_durations, 99) * 1000

    print(f"\n[PERF-02 SLO Verification]")
    print(f"Total Broadcast Duration : {total_broadcast_time_sec * 1000:.2f} ms")
    print(f"p50 Delivery Latency     : {p50_ms:.2f} ms")
    print(f"p95 Delivery Latency     : {p95_ms:.2f} ms")
    print(f"p99 Delivery Latency     : {p99_ms:.2f} ms")

    # SLO assertions
    assert p95_ms <= 500.0, f"p95 broadcast latency {p95_ms:.2f}ms exceeds 500ms SLO"
    assert total_broadcast_time_sec <= 0.500, f"Total broadcast {total_broadcast_time_sec*1000:.2f}ms exceeds 500ms"
