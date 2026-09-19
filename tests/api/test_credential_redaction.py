"""
tests/api/test_credential_redaction.py
--------------------------------------
Verifies Honeypot Credential Redaction (SEC-09):
- Attacker passwords are never stored, logged, or emitted in cleartext.
- Forensic metadata is preserved: truncated SHA-256 hash, length, and reuse fingerprint.
- Sanitizer handles edge cases (empty credentials, unicode, SQL injection strings).
"""
import hashlib
import pytest
from honeypots.credential_sanitizer import sanitize_credential_payload


def test_password_never_stored_in_cleartext():
    """Cleartext password is completely excluded from the sanitized dictionary."""
    raw_pass = "SuperSecretPassword123!@#"
    result = sanitize_credential_payload(username="root", password=raw_pass)

    assert "password" not in result
    assert raw_pass not in str(result)
    assert result["username"] == "root"
    assert result["password_length"] == len(raw_pass)
    assert len(result["password_hash"]) == 12
    assert len(result["credential_reuse_fingerprint"]) == 16


def test_deterministic_forensic_correlation():
    """Identical credentials produce identical hashes and reuse fingerprints for cluster analysis."""
    r1 = sanitize_credential_payload("admin", "toor")
    r2 = sanitize_credential_payload("admin", "toor")
    r3 = sanitize_credential_payload("user", "toor")

    # Same password -> same password_hash
    assert r1["password_hash"] == r2["password_hash"]
    assert r1["password_hash"] == r3["password_hash"]

    # Same username + password -> same reuse fingerprint
    assert r1["credential_reuse_fingerprint"] == r2["credential_reuse_fingerprint"]

    # Different username + same password -> different reuse fingerprint
    assert r1["credential_reuse_fingerprint"] != r3["credential_reuse_fingerprint"]


def test_empty_and_special_payloads():
    """Sanitizer gracefully handles empty inputs and SQL injection payloads."""
    empty_res = sanitize_credential_payload("", "")
    assert empty_res["username"] == ""
    assert empty_res["password_length"] == 0
    assert empty_res["password_hash"] == ""

    sqli_pass = "' OR '1'='1"
    sqli_res = sanitize_credential_payload("admin'--", sqli_pass)
    assert sqli_pass not in str(sqli_res)
    assert sqli_res["password_length"] == len(sqli_pass)
    assert len(sqli_res["password_hash"]) == 12
