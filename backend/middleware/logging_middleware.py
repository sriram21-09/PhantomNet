import time
import uuid
import importlib
import os
import sys
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

# Load our local logging/logger.py without shadowing Python's built-in logging
_logger_path = os.path.join(os.path.dirname(__file__), "..", "logging", "logger.py")
_spec = importlib.util.spec_from_file_location(
    "phantomnet_logger", os.path.abspath(_logger_path)
)
_logger_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_logger_mod)
log_event = _logger_mod.log_event


class SecurityLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        start_time = time.time()

        # Capture request info
        client_ip = request.client.host
        method = request.method
        url = str(request.url)

        # Process request
        response = await call_next(request)

        # Calculate duration
        process_time = time.time() - start_time

        # Determine log level based on status code
        level = "INFO"
        if response.status_code >= 500:
            level = "ERROR"
        elif response.status_code >= 400:
            level = "WARN"

        # Log the event
        log_event(
            honeypot_type="API",
            event="api_request",
            level=level,
            source_ip=client_ip,
            data={
                "request_id": request_id,
                "method": method,
                "url": url,
                "status_code": response.status_code,
                "duration": round(process_time, 4),
                "user_agent": request.headers.get("user-agent"),
            },
        )

        response.headers["X-Request-ID"] = request_id
        return response
