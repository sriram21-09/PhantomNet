import os
import sys
import time
import pytest

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.services.latency_tracer import LatencyTracer, LatencyTraceSpan
from backend.services.telemetry import telemetry_service, END_TO_END_LATENCY_SECONDS


def test_end_to_end_latency_trace_lifecycle():
    """
    OBS-04: Verify end-to-end latency span tracking across all stages:
    T_attack -> T_gateway -> T_db -> T_broadcast
    """
    tracer = LatencyTracer(max_spans=100)
    event_id = "018f6c3a-9921-7000-8000-000000000099"
    t_attack = time.time() - 0.050  # 50ms ago

    span = tracer.start_trace(event_id=event_id, t_attack=t_attack)
    assert span.event_id == event_id
    assert span.t_attack == t_attack
    assert span.t_gateway is not None

    time.sleep(0.010)  # simulate 10ms processing before DB commit
    tracer.mark_db_persistence(event_id)
    assert span.t_db is not None

    time.sleep(0.005)  # simulate 5ms before websocket broadcast
    tracer.mark_broadcast_delivery(event_id)
    assert span.t_broadcast is not None

    # Verify calculated latency metrics
    assert span.ingest_latency_ms is not None
    assert span.ingest_latency_ms >= 40.0  # ~50ms

    assert span.persistence_latency_ms is not None
    assert span.persistence_latency_ms >= 8.0  # ~10ms

    assert span.broadcast_latency_ms is not None
    assert span.broadcast_latency_ms >= 4.0  # ~5ms

    assert span.total_e2e_latency_ms is not None
    assert span.total_e2e_latency_ms >= 50.0  # Total end-to-end >= 50ms

    # Verify serialization
    data = span.to_dict()
    assert data["event_id"] == event_id
    assert data["total_e2e_latency_ms"] == span.total_e2e_latency_ms


def test_latency_tracer_memory_bounded_eviction():
    """
    OBS-04: Verify memory safety: traces above max_spans are evicted.
    """
    tracer = LatencyTracer(max_spans=50)
    for i in range(120):
        tracer.start_trace(event_id=f"evt_{i}")

    assert len(tracer._spans) <= 50
