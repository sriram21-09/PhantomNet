"""
backend/api/rate_limiter.py
----------------------------
Rate limiting helper and FastAPI dependency for Sentinel generation endpoints.
Prevents API resource exhaustion by enforcing maximum calls per client per hour.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List
from fastapi import HTTPException, Request, status

# In-memory sliding window store: ip -> list of request datetimes
_REQUEST_HISTORY: Dict[str, List[datetime]] = defaultdict(list)

MAX_GENERATIONS_PER_HOUR = 10
WINDOW_SECONDS = 3600


def check_rate_limit(request: Request, max_requests: int = MAX_GENERATIONS_PER_HOUR) -> None:
    """
    Check if the requesting client IP has exceeded max_requests within WINDOW_SECONDS.
    Raises HTTP 429 Too Many Requests if exceeded.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)

    # Filter out requests older than cutoff window
    history = [ts for ts in _REQUEST_HISTORY[client_ip] if ts > cutoff]

    if len(history) >= max_requests:
        retry_after = int((history[0] + timedelta(seconds=WINDOW_SECONDS) - now).total_seconds())
        headers = {"Retry-After": str(max(1, retry_after))}
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {max_requests} generation requests per hour allowed.",
            headers=headers,
        )

    # Record current request
    history.append(now)
    _REQUEST_HISTORY[client_ip] = history

    # BUG-40 fix: Periodic cleanup of stale IP keys
    stale_ips = [ip for ip, h in _REQUEST_HISTORY.items()
                 if all(ts <= cutoff for ts in h)]
    for ip in stale_ips:
        del _REQUEST_HISTORY[ip]


def reset_rate_limits() -> None:
    """Utility to clear rate limit cache (for unit testing)."""
    _REQUEST_HISTORY.clear()


def get_rate_limit_status() -> dict:
    """
    Helper function to get current rate limit usage stats for health endpoints.
    Returns tracking info for all active IPs.
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    
    active_limits = {}
    for ip, history in list(_REQUEST_HISTORY.items()):
        # Filter active requests
        active = [ts for ts in history if ts > cutoff]
        if not active:
            # Clean up empty history from our active checks (though we don't delete from dict yet)
            continue
            
        reset_in = int((active[0] + timedelta(seconds=WINDOW_SECONDS) - now).total_seconds())
        active_limits[ip] = {
            "count": len(active),
            "limit": MAX_GENERATIONS_PER_HOUR,
            "reset_in_seconds": max(0, reset_in)
        }
        
    return {
        "active_ips_tracked": len(active_limits),
        "limits": active_limits
    }
