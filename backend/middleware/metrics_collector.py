"""
PhantomNet Prometheus Metrics Collector
========================================

Collects and exposes application metrics in Prometheus format.
Provides a /metrics endpoint for Prometheus scraping.

Metrics:
    phantomnet_requests_total        — Counter (method, path, status)
    phantomnet_request_duration_ms   — Histogram (method, path)
    phantomnet_active_connections    — Gauge
    phantomnet_cache_hits_total      — Counter
    phantomnet_cache_misses_total    — Counter
"""

import time
import logging
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Lightweight Prometheus-compatible metrics collector.
    No external dependencies — generates Prometheus text format directly.
    """

    def __init__(self):
        # Counters: {label_key: count}
        self.request_count = defaultdict(int)     # (method, path, status) → count
        self.error_count = defaultdict(int)        # (method, path) → count

        # Histogram buckets for response time (ms)
        self.duration_buckets = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
        self.duration_counts = defaultdict(lambda: [0] * len(self.duration_buckets))
        self.duration_sum = defaultdict(float)
        self.duration_total = defaultdict(int)

        # Gauges
        self.active_connections = 0

    def record_request(self, method: str, path: str, status: int, duration_ms: float):
        """Record a completed request."""
        # Normalize path (remove query params and IDs for grouping)
        normalized_path = self._normalize_path(path)

        # Counter
        self.request_count[(method, normalized_path, status)] += 1

        # Error tracking
        if status >= 400:
            self.error_count[(method, normalized_path)] += 1

        # Duration histogram
        key = (method, normalized_path)
        self.duration_sum[key] += duration_ms
        self.duration_total[key] += 1
        for i, bucket in enumerate(self.duration_buckets):
            if duration_ms <= bucket:
                self.duration_counts[key][i] += 1

    def _normalize_path(self, path: str) -> str:
        """Normalize path for metric grouping (collapse IDs)."""
        parts = path.split("/")
        normalized = []
        for part in parts:
            # Replace numeric segments or UUID-like segments with placeholder
            if part.isdigit() or (len(part) > 8 and "-" in part):
                normalized.append("{id}")
            else:
                normalized.append(part)
        return "/".join(normalized)

    def to_prometheus(self) -> str:
        """Generate Prometheus text exposition format."""
        lines = []

        # Request counter
        lines.append("# HELP phantomnet_requests_total Total HTTP requests")
        lines.append("# TYPE phantomnet_requests_total counter")
        for (method, path, status), count in sorted(self.request_count.items()):
            lines.append(
                f'phantomnet_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}'
            )

        # Error counter
        lines.append("")
        lines.append("# HELP phantomnet_errors_total Total HTTP errors (4xx/5xx)")
        lines.append("# TYPE phantomnet_errors_total counter")
        for (method, path), count in sorted(self.error_count.items()):
            lines.append(
                f'phantomnet_errors_total{{method="{method}",path="{path}"}} {count}'
            )

        # Duration histogram
        lines.append("")
        lines.append("# HELP phantomnet_request_duration_ms Request duration in milliseconds")
        lines.append("# TYPE phantomnet_request_duration_ms histogram")
        for (method, path), counts in sorted(self.duration_counts.items()):
            cumulative = 0
            for i, bucket in enumerate(self.duration_buckets):
                cumulative += counts[i]
                lines.append(
                    f'phantomnet_request_duration_ms_bucket{{method="{method}",path="{path}",le="{bucket}"}} {cumulative}'
                )
            lines.append(
                f'phantomnet_request_duration_ms_bucket{{method="{method}",path="{path}",le="+Inf"}} {self.duration_total[(method, path)]}'
            )
            lines.append(
                f'phantomnet_request_duration_ms_sum{{method="{method}",path="{path}"}} {self.duration_sum[(method, path)]:.2f}'
            )
            lines.append(
                f'phantomnet_request_duration_ms_count{{method="{method}",path="{path}"}} {self.duration_total[(method, path)]}'
            )

        # Active connections gauge
        lines.append("")
        lines.append("# HELP phantomnet_active_connections Current active connections")
        lines.append("# TYPE phantomnet_active_connections gauge")
        lines.append(f"phantomnet_active_connections {self.active_connections}")

        return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────
# Global metrics instance
# ──────────────────────────────────────────────
metrics = MetricsCollector()


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    Middleware that collects request metrics for Prometheus.
    """

    async def dispatch(self, request: Request, call_next):
        # Skip metrics endpoint itself
        if request.url.path == "/metrics":
            return await call_next(request)

        metrics.active_connections += 1
        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000

            metrics.record_request(
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=duration_ms,
            )

            return response
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            metrics.record_request(
                method=request.method,
                path=request.url.path,
                status=500,
                duration_ms=duration_ms,
            )
            raise
        finally:
            metrics.active_connections -= 1


def get_metrics_response():
    """Return Prometheus-formatted metrics as a PlainTextResponse."""
    return PlainTextResponse(
        content=metrics.to_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
