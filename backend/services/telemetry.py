"""
backend/services/telemetry.py
-----------------------------
Prometheus Telemetry & Metrics Service (OBS-03, OBS-04).

Defines Prometheus metrics for real-time monitoring of ingestion rates,
latencies, queue depths, error counters, and component health.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# Standard shared registry
REGISTRY = CollectorRegistry(auto_describe=True)

# 1. Ingestion Counters & Latencies
INGESTION_EVENTS_TOTAL = Counter(
    "phantomnet_events_total",
    "Total events processed by Ingestion Gateway",
    ["honeypot_id", "event_type", "status"],
    registry=REGISTRY,
)

INGESTION_LATENCY_SECONDS = Histogram(
    "phantomnet_ingestion_latency_seconds",
    "Time taken to ingest and acknowledge events at the gateway",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
    registry=REGISTRY,
)

END_TO_END_LATENCY_SECONDS = Histogram(
    "phantomnet_end_to_end_latency_seconds",
    "Total end-to-end latency from attack capture (T_attack) to dashboard broadcast (T_broadcast)",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
    registry=REGISTRY,
)

# 2. Queue & Persistence Metrics
STREAM_QUEUE_DEPTH = Gauge(
    "phantomnet_stream_queue_depth",
    "Number of pending messages in the Redis Stream queue",
    ["stream_name"],
    registry=REGISTRY,
)

PEL_UNACKNOWLEDGED_MESSAGES = Gauge(
    "phantomnet_pel_unacknowledged_messages",
    "Number of unacknowledged messages in the consumer group pending list",
    ["consumer_group"],
    registry=REGISTRY,
)

# 3. System & Degraded Operations
DEGRADED_MODE = Gauge(
    "phantomnet_degraded_mode",
    "Indicates whether a component is operating in degraded mode (1 = degraded, 0 = normal)",
    ["component"],
    registry=REGISTRY,
)

ERRORS_TOTAL = Counter(
    "phantomnet_errors_total",
    "Total errors encountered across components",
    ["component", "error_type"],
    registry=REGISTRY,
)

HONEYPOT_STATUS = Gauge(
    "phantomnet_honeypot_status",
    "Status of honeypot nodes (1 = active/up, 0 = down)",
    ["honeypot_id", "port"],
    registry=REGISTRY,
)

# Initialize default degraded modes
for comp in ["ml_engine", "ollama_llm", "geoip", "pcap"]:
    DEGRADED_MODE.labels(component=comp).set(0)


class TelemetryService:
    """Manages telemetry recording and Prometheus export."""

    @staticmethod
    def record_ingest(honeypot_id: str, event_type: str, status: str, duration_sec: float) -> None:
        INGESTION_EVENTS_TOTAL.labels(
            honeypot_id=honeypot_id, event_type=event_type, status=status
        ).inc()
        INGESTION_LATENCY_SECONDS.observe(duration_sec)

    @staticmethod
    def record_e2e_latency(latency_sec: float) -> None:
        END_TO_END_LATENCY_SECONDS.observe(max(0.0, latency_sec))

    @staticmethod
    def set_stream_depth(stream_name: str, depth: int) -> None:
        STREAM_QUEUE_DEPTH.labels(stream_name=stream_name).set(depth)

    @staticmethod
    def set_pel_depth(consumer_group: str, count: int) -> None:
        PEL_UNACKNOWLEDGED_MESSAGES.labels(consumer_group=consumer_group).set(count)

    _degraded_state: Dict[str, bool] = {}

    @classmethod
    def set_degraded(cls, component: str, is_degraded: bool) -> None:
        cls._degraded_state[component] = is_degraded
        DEGRADED_MODE.labels(component=component).set(1 if is_degraded else 0)

    @classmethod
    def is_degraded(cls, component: str) -> bool:
        return cls._degraded_state.get(component, False)

    @staticmethod
    def record_error(component: str, error_type: str) -> None:
        ERRORS_TOTAL.labels(component=component, error_type=error_type).inc()

    @staticmethod
    def set_honeypot_status(honeypot_id: str, port: int, is_up: bool) -> None:
        HONEYPOT_STATUS.labels(honeypot_id=honeypot_id, port=str(port)).set(1 if is_up else 0)

    @staticmethod
    def export_metrics() -> tuple[bytes, str]:
        """Generates Prometheus text payload."""
        return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


telemetry_service = TelemetryService()
