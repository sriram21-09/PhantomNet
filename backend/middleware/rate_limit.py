"""
Rate limiting middleware and dependency.
"""
from fastapi import Request, HTTPException
from middleware.cache import TTLCache

# Simple rate limiter tracking requests by IP (10 requests per minute)
_rate_limiter = TTLCache(default_ttl=60, max_size=2000)
RATE_LIMIT_MAX_REQUESTS = 30

def rate_limit_dependency(request: Request):
    """
    Dependency to rate limit sensitive API endpoints.
    Allows 30 requests per minute per IP.
    """
    # Prefer X-Forwarded-For for clients behind proxies
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    elif request.client:
        ip = request.client.host
    else:
        ip = "unknown"
    
    # Use path and IP for granularity
    key = f"rate_limit:{ip}:{request.url.path}"
    
    current_count = _rate_limiter.get(key)
    if current_count is None:
        current_count = 0
        
    if current_count >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later."
        )
        
    _rate_limiter.set(key, current_count + 1, ttl=60)
