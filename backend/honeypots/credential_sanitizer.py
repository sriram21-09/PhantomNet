"""
Credential Sanitization Module for Honeypots
Prevents storing cleartext attacker credentials while preserving forensic utility:
- Truncated SHA-256 hash for correlation
- Length of password
- Salted/composite credential-reuse fingerprint (hash of username:password)
"""
import hashlib
from typing import Dict, Any


def sanitize_credential_payload(username: str = "", password: str = "") -> Dict[str, Any]:
    """
    Sanitizes credentials submitted to honeypots by hashing and extracting metadata.
    Never stores or logs the cleartext password.
    """
    safe_user = str(username or "")
    safe_pass = str(password or "")

    pw_hash = (
        hashlib.sha256(safe_pass.encode("utf-8", errors="ignore")).hexdigest()[:12]
        if safe_pass
        else ""
    )
    reuse_fp = (
        hashlib.sha256(f"{safe_user}:{safe_pass}".encode("utf-8", errors="ignore")).hexdigest()[:16]
        if (safe_user or safe_pass)
        else ""
    )

    return {
        "username": safe_user,
        "password_hash": pw_hash,
        "password_length": len(safe_pass),
        "credential_reuse_fingerprint": reuse_fp,
    }
