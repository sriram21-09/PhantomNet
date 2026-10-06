"""
System Configuration Service for PhantomNet.

Provides unified, cached, and validated access to runtime configuration
stored in PostgreSQL `system_config` table, bridging the gap between Admin Panel
settings and runtime subsystems (ML Engine, Response Executor, SIEM Exporters,
Sentinel Email Notifiers, Honeypot Nodes, and Database Maintenance).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session
from database.database import SessionLocal
from database.models import SystemConfig

logger = logging.getLogger("phantomnet.config_service")

# Thread-safe in-memory cache
_CACHE: Dict[str, Tuple[str, float]] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_TTL_SECONDS = 15.0


def invalidate_config_cache(key: Optional[str] = None) -> None:
    """Invalidate cached config values."""
    with _CACHE_LOCK:
        if key:
            _CACHE.pop(key, None)
        else:
            _CACHE.clear()


def get_config_value(key: str, default: Optional[str] = None, db: Optional[Session] = None) -> Optional[str]:
    """Retrieve raw string configuration value with cache and DB fallback."""
    now = time.time()

    # 1. Check in-memory cache
    with _CACHE_LOCK:
        if key in _CACHE:
            val, expiry = _CACHE[key]
            if now < expiry:
                return val

    # 2. Query database
    owns_session = False
    if db is None:
        try:
            db = SessionLocal()
            owns_session = True
        except Exception as e:
            logger.warning("Could not establish DB session for config key '%s': %s", key, e)
            return default

    try:
        cfg = db.query(SystemConfig).filter(SystemConfig.key == key).first()
        if cfg and cfg.value is not None:
            val = str(cfg.value)
            with _CACHE_LOCK:
                _CACHE[key] = (val, now + _CACHE_TTL_SECONDS)
            return val
    except Exception as e:
        logger.warning("Failed querying system_config for key '%s': %s", key, e)
    finally:
        if owns_session:
            db.close()

    # Fallback to provided default or environment variable if matching
    env_val = os.getenv(key.upper())
    return env_val if env_val is not None else default


def get_config_bool(key: str, default: bool = False, db: Optional[Session] = None) -> bool:
    """Retrieve configuration value parsed as boolean."""
    val = get_config_value(key, default=None, db=db)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "on", "enabled")


def get_config_int(key: str, default: int = 0, db: Optional[Session] = None) -> int:
    """Retrieve configuration value parsed as integer."""
    val = get_config_value(key, default=None, db=db)
    if val is None:
        return default
    try:
        return int(float(val.strip()))
    except (ValueError, TypeError):
        return default


def get_config_float(key: str, default: float = 0.0, db: Optional[Session] = None) -> float:
    """Retrieve configuration value parsed as float."""
    val = get_config_value(key, default=None, db=db)
    if val is None:
        return default
    try:
        return float(val.strip())
    except (ValueError, TypeError):
        return default


def get_config_str(key: str, default: str = "", db: Optional[Session] = None) -> str:
    """Retrieve configuration value parsed as non-empty string."""
    val = get_config_value(key, default=None, db=db)
    if val is None or not val.strip():
        return default
    return val.strip()


def set_config_value(key: str, value: str, category: str, db: Optional[Session] = None) -> SystemConfig:
    """Persist or update configuration value and invalidate cache."""
    owns_session = False
    if db is None:
        db = SessionLocal()
        owns_session = True

    try:
        cfg = db.query(SystemConfig).filter(SystemConfig.key == key).first()
        is_llm_toggle = key == "sentinel_llm_enabled"
        llm_val = value.strip().lower() in ("1", "true", "yes", "on") if is_llm_toggle else False

        if cfg:
            cfg.value = value
            cfg.category = category
            if is_llm_toggle and hasattr(cfg, "sentinel_llm_enabled"):
                cfg.sentinel_llm_enabled = llm_val
        else:
            cfg = SystemConfig(key=key, value=value, category=category)
            if is_llm_toggle and hasattr(cfg, "sentinel_llm_enabled"):
                cfg.sentinel_llm_enabled = llm_val
            db.add(cfg)

        db.commit()
        db.refresh(cfg)
        invalidate_config_cache(key)
        logger.info("SystemConfig updated: %s=%s (category=%s)", key, value, category)
        return cfg
    finally:
        if owns_session:
            db.close()
