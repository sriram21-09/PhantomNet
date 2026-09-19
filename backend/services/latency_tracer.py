"""
backend/services/latency_tracer.py
----------------------------------
End-to-End Latency Tracing & Verification Service (OBS-04).

Tracks high-precision timestamps through each stage of the event lifecycle:
  T_attack     : Capture timestamp from honeypot sensor (producer)
  T_gateway    : Ingestion Gateway receipt & Redis Stream enqueue timestamp
  T_db         : Database worker commit & persistence timestamp
  T_broadcast  : Real-time WebSocket delivery timestamp
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional
from services.telemetry import telemetry_service


@dataclass
class LatencyTraceSpan:
    event_id: str
    t_attack: float  # Unix epoch seconds (float)
    t_gateway: Optional[float] = None
    t_db: Optional[float] = None
    t_broadcast: Optional[float] = None

    def mark_gateway(self) -> None:
        self.t_gateway = time.time()

    def mark_db(self) -> None:
        self.t_db = time.time()

    def mark_broadcast(self) -> None:
        self.t_broadcast = time.time()
        if self.t_attack:
            total_sec = self.t_broadcast - self.t_attack
            telemetry_service.record_e2e_latency(total_sec)

    @property
    def ingest_latency_ms(self) -> Optional[float]:
        if self.t_gateway is not None and self.t_attack is not None:
            return round((self.t_gateway - self.t_attack) * 1000, 2)
        return None

    @property
    def persistence_latency_ms(self) -> Optional[float]:
        if self.t_db is not None and self.t_gateway is not None:
            return round((self.t_db - self.t_gateway) * 1000, 2)
        return None

    @property
    def broadcast_latency_ms(self) -> Optional[float]:
        if self.t_broadcast is not None and self.t_db is not None:
            return round((self.t_broadcast - self.t_db) * 1000, 2)
        return None

    @property
    def total_e2e_latency_ms(self) -> Optional[float]:
        if self.t_broadcast is not None and self.t_attack is not None:
            return round((self.t_broadcast - self.t_attack) * 1000, 2)
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "t_attack": self.t_attack,
            "t_gateway": self.t_gateway,
            "t_db": self.t_db,
            "t_broadcast": self.t_broadcast,
            "ingest_latency_ms": self.ingest_latency_ms,
            "persistence_latency_ms": self.persistence_latency_ms,
            "broadcast_latency_ms": self.broadcast_latency_ms,
            "total_e2e_latency_ms": self.total_e2e_latency_ms,
        }


class LatencyTracer:
    """In-memory active span tracker for end-to-end telemetry verification."""

    def __init__(self, max_spans: int = 1000):
        self._spans: Dict[str, LatencyTraceSpan] = {}
        self._max_spans = max_spans

    def start_trace(self, event_id: str, t_attack: Optional[float] = None) -> LatencyTraceSpan:
        if len(self._spans) >= self._max_spans:
            # Drop oldest 100 entries to prevent memory leak
            keys = list(self._spans.keys())[:100]
            for k in keys:
                self._spans.pop(k, None)

        span = LatencyTraceSpan(
            event_id=event_id,
            t_attack=t_attack if t_attack is not None else time.time(),
        )
        span.mark_gateway()
        self._spans[event_id] = span
        return span

    def get_trace(self, event_id: str) -> Optional[LatencyTraceSpan]:
        return self._spans.get(event_id)

    def mark_db_persistence(self, event_id: str) -> Optional[LatencyTraceSpan]:
        span = self._spans.get(event_id)
        if span:
            span.mark_db()
        return span

    def mark_broadcast_delivery(self, event_id: str) -> Optional[LatencyTraceSpan]:
        span = self._spans.get(event_id)
        if span:
            span.mark_broadcast()
        return span


latency_tracer = LatencyTracer()
