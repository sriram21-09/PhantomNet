"""
tests/api/test_origin_auth.py
----------------------------
Verifies Honeypot Producer Origin Authentication (SEC-09):
- HMAC-SHA256 signature creation and constant-time verification.
- Enforces max drift window (60 seconds) to prevent replay.
- Verifies envelope signing and tampering detection.
"""
import time
import pytest
from services.origin_auth import (
    generate_origin_signature,
    verify_origin_signature,
    sign_event_dict,
    verify_event_dict,
    get_honeypot_secret_key
)


def test_valid_origin_signature():
    payload = b'{"event": "ssh_login", "ip": "1.2.3.4"}'
    ts = int(time.time())
    sig = generate_origin_signature(payload, ts, secret_key="test-secret-key-12345678901234567890")

    is_valid, reason = verify_origin_signature(
        payload, ts, sig, secret_key="test-secret-key-12345678901234567890"
    )
    assert is_valid is True
    assert reason == "Valid origin signature"


def test_origin_signature_tampered_payload_rejected():
    payload = b'{"event": "ssh_login", "ip": "1.2.3.4"}'
    ts = int(time.time())
    sig = generate_origin_signature(payload, ts, secret_key="test-secret-key-12345678901234567890")

    tampered_payload = b'{"event": "ssh_login", "ip": "9.9.9.9"}'
    is_valid, reason = verify_origin_signature(
        tampered_payload, ts, sig, secret_key="test-secret-key-12345678901234567890"
    )
    assert is_valid is False
    assert "mismatch" in reason.lower()


def test_origin_signature_timestamp_drift_rejected():
    payload = b'{"event": "ssh_login", "ip": "1.2.3.4"}'
    # Timestamp from 10 minutes ago
    expired_ts = int(time.time()) - 600
    sig = generate_origin_signature(payload, expired_ts, secret_key="test-secret-key-12345678901234567890")

    is_valid, reason = verify_origin_signature(
        payload, expired_ts, sig, secret_key="test-secret-key-12345678901234567890", max_drift_seconds=60
    )
    assert is_valid is False
    assert "drift" in reason.lower()


def test_sign_and_verify_event_dict():
    event = {
        "event_id": "018e5f2a-7b3c-7000-8000-000000000001",
        "honeypot": "ssh",
        "src_ip": "198.51.100.22",
        "data": {"cmd": "uname -a"}
    }
    signed_event = sign_event_dict(event, secret_key="test-secret-key-12345678901234567890")
    assert "_origin_auth" in signed_event
    assert "signature" in signed_event["_origin_auth"]
    assert "timestamp" in signed_event["_origin_auth"]

    is_valid, reason = verify_event_dict(signed_event, secret_key="test-secret-key-12345678901234567890")
    assert is_valid is True

    # Tampering with payload
    signed_event["src_ip"] = "203.0.113.55"
    tampered_valid, tampered_reason = verify_event_dict(signed_event, secret_key="test-secret-key-12345678901234567890")
    assert tampered_valid is False
