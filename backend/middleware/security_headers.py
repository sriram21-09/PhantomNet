"""
Security Headers & CSRF Middleware for PhantomNet (Phase 1).

Adds defense-in-depth security headers to every response (CSP, HSTS, X-Content-Type-Options, etc.)
and enforces CSRF protections for cookie-authenticated mutating HTTP requests.
"""

import logging
import os
from typing import Set
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("middleware.security")

# Allowed origins for CORS, CSRF, and WebSocket connections
_DEFAULT_ALLOWED_ORIGINS = {
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
}

env_origins = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS: Set[str] = (
    {orig.strip() for orig in env_origins.split(",") if orig.strip()}
    if env_origins
    else _DEFAULT_ALLOWED_ORIGINS
)

# Mutating methods that require CSRF validation when using cookie sessions
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths exempt from CSRF (login, refresh, public ingestion)
CSRF_EXEMPT_PATHS = {
    "/api/v1/admin/login",
    "/api/v1/admin/refresh",
    "/api/v1/admin/logout",
    "/api/v1/ingest/event",
    "/docs",
    "/redoc",
    "/openapi.json",
}


class SecurityHeadersAndCSRFMiddleware(BaseHTTPMiddleware):
    """Adds security headers and validates CSRF tokens on cookie-authenticated mutations."""

    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method
        path = request.url.path

        # CSRF Protection:
        # If the request is a mutating method, uses cookie auth, and has no Authorization header
        if method in MUTATING_METHODS and path not in CSRF_EXEMPT_PATHS:
            has_auth_cookie = "phantomnet_access_token" in request.cookies or "access_token" in request.cookies
            has_bearer_header = "authorization" in request.headers

            # Only enforce CSRF on requests relying on ambient cookie credentials
            if has_auth_cookie and not has_bearer_header:
                csrf_header = request.headers.get("x-csrf-token") or request.headers.get("x-requested-with")
                if not csrf_header:
                    logger.warning(
                        "🚨 CSRF REJECTED: Missing X-CSRF-Token or X-Requested-With header on %s %s from %s",
                        method,
                        path,
                        request.client.host if request.client else "unknown",
                    )
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF validation failed: Missing custom request header"},
                    )

                # Origin / Referer check
                origin = request.headers.get("origin")
                referer = request.headers.get("referer")
                request_origin = None

                if origin:
                    request_origin = origin.rstrip("/")
                elif referer:
                    parsed = urlparse(referer)
                    request_origin = f"{parsed.scheme}://{parsed.netloc}"

                if request_origin and request_origin not in ALLOWED_ORIGINS:
                    logger.warning(
                        "🚨 CSRF REJECTED: Disallowed origin %s on %s %s",
                        request_origin,
                        method,
                        path,
                    )
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF validation failed: Origin not allowed"},
                    )

        # Process request
        response: Response = await call_next(request)

        # Apply Hardened Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # HSTS (2 years, subdomains, preload)
        if os.getenv("ENVIRONMENT", "local").lower() in ["production", "prod"]:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

        # Content Security Policy (allows Swagger docs while securing app)
        if not path.startswith(("/docs", "/redoc", "/openapi.json")):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self' ws: wss:; "
                "frame-ancestors 'none';"
            )

        return response
