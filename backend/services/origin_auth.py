"""
Honeypot Producer Origin Authentication Module (HMAC-SHA256)
Guarantees event provenance and prevents unauthorized / forged event injection
into the ingestion pipeline.
"""
import os
import time
import hmac
import hashlib
import json
from typing import Tuple, Dict, Any, Optional

DEFAULT_INSECURE_KEYS = {
    "phantomnet-honeypot-secret-change-in-prod",
    "secret",
    "password",
    "changeme",
    "default_key",
}

def get_honeypot_secret_key() -> str:
    """
    Retrieves the honeypot origin signing secret key.
    Enforces non-trivial secret key in production environments.
    """
    key = os.getenv("HONEYPOT_SECRET_KEY", "phantomnet-honeypot-secret-change-in-prod")
    env = os.getenv("ENVIRONMENT", "development").lower()
    if env == "production":
        if not key or key in DEFAULT_INSECURE_KEYS or len(key) < 32:
            raise RuntimeError(
                "CRITICAL: Production honeypot origin secret key (HONEYPOT_SECRET_KEY) "
                "must be explicitly set and >= 32 characters."
            )
    return key


def compute_payload_digest(payload_bytes: bytes) -> str:
    """Computes SHA-256 digest of arbitrary payload bytes."""
    return hashlib.sha256(payload_bytes).hexdigest()


def generate_origin_signature(
    payload_bytes: bytes,
    timestamp: int,
    secret_key: Optional[str] = None
) -> str:
    """
    Generates an HMAC-SHA256 signature for a payload and epoch timestamp.
    Message format: "{timestamp}:{sha256(payload_bytes)}"
    """
    key = (secret_key or get_honeypot_secret_key()).encode("utf-8")
    digest = compute_payload_digest(payload_bytes)
    canonical_msg = f"{timestamp}:{digest}".encode("utf-8")
    return hmac.new(key, canonical_msg, hashlib.sha256).hexdigest()


def verify_origin_signature(
    payload_bytes: bytes,
    timestamp: int,
    signature: str,
    secret_key: Optional[str] = None,
    max_drift_seconds: int = 60,
    current_time: Optional[int] = None
) -> Tuple[bool, str]:
    """
    Verifies the HMAC-SHA256 origin signature and freshness window.
    Returns (is_valid: bool, reason: str).
    """
    if not signature:
        return False, "Missing origin signature"

    now = int(current_time if current_time is not None else time.time())
    if abs(now - timestamp) > max_drift_seconds:
        return False, f"Timestamp drift exceeded: {abs(now - timestamp)}s > {max_drift_seconds}s"

    key = (secret_key or get_honeypot_secret_key()).encode("utf-8")
    expected_sig = generate_origin_signature(payload_bytes, timestamp, secret_key)

    if not hmac.compare_digest(expected_sig, signature):
        return False, "Signature mismatch / invalid origin credentials"

    return True, "Valid origin signature"


def sign_event_dict(
    event_dict: Dict[str, Any],
    secret_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Appends '_origin_auth' metadata {timestamp, signature} to an event dictionary.
    Serializes event with sorted keys for deterministic verification.
    """
    clean_dict = {k: v for k, v in event_dict.items() if k != "_origin_auth"}
    payload_bytes = json.dumps(clean_dict, sort_keys=True).encode("utf-8")
    ts = int(time.time())
    sig = generate_origin_signature(payload_bytes, ts, secret_key)
    
    result = dict(clean_dict)
    result["_origin_auth"] = {
        "timestamp": ts,
        "signature": sig,
    }
    return result


def verify_event_dict(
    event_dict: Dict[str, Any],
    secret_key: Optional[str] = None,
    max_drift_seconds: int = 60,
    current_time: Optional[int] = None
) -> Tuple[bool, str]:
    """
    Verifies the '_origin_auth' metadata embedded inside an event dictionary.
    """
    origin_auth = event_dict.get("_origin_auth")
    if not isinstance(origin_auth, dict):
        return False, "Missing or malformed '_origin_auth' envelope"

    ts = origin_auth.get("timestamp")
    sig = origin_auth.get("signature")
    if ts is None or not sig:
        return False, "Incomplete '_origin_auth' metadata"

    clean_dict = {k: v for k, v in event_dict.items() if k != "_origin_auth"}
    payload_bytes = json.dumps(clean_dict, sort_keys=True).encode("utf-8")
    return verify_origin_signature(payload_bytes, ts, sig, secret_key, max_drift_seconds, current_time)
