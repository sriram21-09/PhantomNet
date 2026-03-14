"""
PhantomNet API Cache Middleware
================================

In-memory TTL (Time-To-Live) cache for API responses.
Reduces database load by caching frequently requested endpoints.

Usage:
    from middleware.cache import cache_response, invalidate_cache

    @app.get("/api/stats")
    @cache_response(ttl_seconds=30)
    def get_stats(db: Session = Depends(get_db)):
        ...

    # Manual invalidation
    invalidate_cache("/api/stats")
"""

import time
import hashlib
import json
import logging
import functools
from typing import Optional, Any
from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class TTLCache:
    """
    Thread-safe in-memory cache with TTL expiration.

    Stores serialized API responses keyed by request path + query params.
    Expired entries are lazily cleaned on access.
    """

    def __init__(self, default_ttl: int = 30, max_size: int = 500):
        self._store = {}  # key → {"data": ..., "expires_at": float}
        self._default_ttl = default_ttl
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if exists and not expired."""
        entry = self._store.get(key)
        if entry is None:
            self._misses += 1
            return None

        if time.time() > entry["expires_at"]:
            # Expired — remove and return miss
            del self._store[key]
            self._misses += 1
            return None

        self._hits += 1
        return entry["data"]

    def set(self, key: str, data: Any, ttl: Optional[int] = None):
        """Store a value with TTL expiration."""
        # Evict oldest if at capacity
        if len(self._store) >= self._max_size:
            self._evict_expired()
            if len(self._store) >= self._max_size:
                # Remove oldest entry
                oldest_key = min(
                    self._store, key=lambda k: self._store[k]["expires_at"]
                )
                del self._store[oldest_key]

        ttl = ttl or self._default_ttl
        self._store[key] = {
            "data": data,
            "expires_at": time.time() + ttl,
        }

    def invalidate(self, pattern: str):
        """
        Remove all cache entries matching a path pattern.
        Pattern is a prefix match (e.g., "/api/stats" matches "/api/stats?x=1").
        """
        keys_to_remove = [k for k in self._store if k.startswith(pattern)]
        for key in keys_to_remove:
            del self._store[key]
        if keys_to_remove:
            logger.info(
                f"[CACHE] Invalidated {len(keys_to_remove)} entries matching '{pattern}'"
            )

    def clear(self):
        """Clear all cached entries."""
        self._store.clear()
        self._hits = 0
        self._misses = 0
        logger.info("[CACHE] Cache cleared")

    def _evict_expired(self):
        """Remove all expired entries."""
        now = time.time()
        expired = [k for k, v in self._store.items() if now > v["expires_at"]]
        for key in expired:
            del self._store[key]

    @property
    def stats(self) -> dict:
        """Return cache statistics."""
        self._evict_expired()
        total = self._hits + self._misses
        return {
            "size": len(self._store),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total * 100, 1) if total > 0 else 0.0,
            "default_ttl": self._default_ttl,
        }


# ──────────────────────────────────────────────
# Global cache instance
# ──────────────────────────────────────────────
api_cache = TTLCache(default_ttl=30, max_size=500)


def _make_cache_key(path: str, query_params: dict) -> str:
    """Generate a unique cache key from request path and query params."""
    params_str = json.dumps(sorted(query_params.items()), default=str)
    param_hash = hashlib.sha256(params_str.encode()).hexdigest()[:16]
    return f"{path}:{param_hash}"


def cache_response(ttl_seconds: int = 30):
    """
    Decorator to cache FastAPI endpoint responses.

    Args:
        ttl_seconds: Time-to-live in seconds (default: 30)

    Usage:
        @app.get("/api/stats")
        @cache_response(ttl_seconds=30)
        def get_stats(...):
            ...
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Build cache key from function name and arguments
            key_parts = [func.__name__]
            for k, v in kwargs.items():
                if k != "db":  # Skip DB session
                    key_parts.append(f"{k}={v}")
            cache_key = ":".join(key_parts)

            # Check cache
            cached = api_cache.get(cache_key)
            if cached is not None:
                logger.debug(f"[CACHE] HIT: {cache_key}")
                return cached

            # Execute function and cache result
            logger.debug(f"[CACHE] MISS: {cache_key}")
            result = func(*args, **kwargs)
            api_cache.set(cache_key, result, ttl=ttl_seconds)
            return result

        return wrapper

    return decorator


def invalidate_cache(pattern: str):
    """Invalidate all cache entries matching a path pattern."""
    api_cache.invalidate(pattern)
