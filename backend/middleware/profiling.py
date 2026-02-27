"""
PhantomNet Request Profiling Middleware
========================================

Measures request processing time and memory usage for every API call.
Adds performance headers to responses and logs slow requests.

Headers added:
    X-Process-Time: Request duration in milliseconds
    X-Memory-Delta: Memory change during request (KB)
"""

import time
import tracemalloc
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger(__name__)

# Threshold for slow request warning (milliseconds)
SLOW_REQUEST_THRESHOLD_MS = 500


class ProfilingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that profiles every request:
    - Measures response time (ms)
    - Tracks memory delta (KB)
    - Logs slow requests (>500ms)
    - Adds profiling headers to responses
    """

    def __init__(self, app, enable_memory_tracking: bool = False):
        super().__init__(app)
        self.enable_memory = enable_memory_tracking
        self._request_count = 0
        self._total_time_ms = 0.0
        self._slow_requests = 0

        if self.enable_memory and not tracemalloc.is_tracing():
            tracemalloc.start()
            logger.info("[PROFILER] Memory tracking enabled via tracemalloc")

        logger.info("[PROFILER] Request profiling middleware initialized")

    async def dispatch(self, request: Request, call_next):
        # Start timing
        start_time = time.perf_counter()

        # Snapshot memory before (if enabled)
        mem_before = 0
        if self.enable_memory:
            mem_before = tracemalloc.get_traced_memory()[0]

        # Process request
        response = await call_next(request)

        # Calculate duration
        duration_ms = (time.perf_counter() - start_time) * 1000
        self._request_count += 1
        self._total_time_ms += duration_ms

        # Calculate memory delta (if enabled)
        mem_delta_kb = 0.0
        if self.enable_memory:
            mem_after = tracemalloc.get_traced_memory()[0]
            mem_delta_kb = round((mem_after - mem_before) / 1024, 2)

        # Add headers
        response.headers["X-Process-Time"] = f"{duration_ms:.2f}ms"
        if self.enable_memory:
            response.headers["X-Memory-Delta"] = f"{mem_delta_kb}KB"

        # Log slow requests
        path = request.url.path
        method = request.method

        if duration_ms > SLOW_REQUEST_THRESHOLD_MS:
            self._slow_requests += 1
            logger.warning(
                f"[SLOW] {method} {path} took {duration_ms:.0f}ms "
                f"(threshold: {SLOW_REQUEST_THRESHOLD_MS}ms)"
            )
        else:
            logger.debug(f"[PROFILER] {method} {path} — {duration_ms:.1f}ms")

        return response

    @property
    def stats(self) -> dict:
        """Return profiling statistics."""
        avg_time = (
            round(self._total_time_ms / self._request_count, 2)
            if self._request_count > 0
            else 0.0
        )
        return {
            "total_requests": self._request_count,
            "avg_response_time_ms": avg_time,
            "slow_requests": self._slow_requests,
            "slow_threshold_ms": SLOW_REQUEST_THRESHOLD_MS,
            "memory_tracking": self.enable_memory,
        }
