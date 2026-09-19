"""
Test suite verifying OPS-05: Secret Rotation Lifecycle Evidence.
Empirically verifies:
1. Honeypot HMAC origin key rotation rejects retired secret keys,
   accepts new secret keys, and continues uninterrupted stream ingestion.
2. JWT signing secret rotation rejects tokens signed with retired secrets
   while accepting new credentials without service restarts or downtime.
"""

import os
import time
import hmac
import hashlib
import json
import pytest
from datetime import datetime, timezone
import fakeredis

from backend.schemas.event_envelope import EventEnvelope, generate_uuidv7
from backend.services.ingestion_gateway import IngestionGateway, IngestionAuthenticationError
from backend.services.origin_auth import generate_origin_signature, verify_origin_signature
from backend.middleware.auth import create_access_token, decode_token


def test_honeypot_hmac_secret_rotation_lifecycle():
    """
    OPS-05: Verify Honeypot HMAC secret key rotation:
    1. Active secret K1 produces valid signatures accepted by Ingestion Gateway.
    2. Rotation occurs: Gateway transitions active secret to K2.
    3. Old signature signed with K1 is rejected.
    4. New signature signed with K2 is accepted.
    5. Ingestion pipeline experiences zero downtime.
    """
    fake_r = fakeredis.FakeRedis()
    key_v1 = "initial-production-secret-key-version-1-32chars"
    key_v2 = "rotated-production-secret-key-version-2-32chars"

    # Gateway initialized with Key V1
    gateway = IngestionGateway(
        redis_client=fake_r,
        secret_key=key_v1,
        stream_key="events:stream:ops05",
    )

    now_ts = int(time.time())
    payload = {
        "event_id": generate_uuidv7(),
        "honeypot_id": "ssh-honeypot-01",
        "event_type": "AUTH_FAILED",
        "src_ip": "198.51.100.22",
        "dst_port": 22,
        "protocol": "TCP",
    }
    raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

    # 1. Sign with Key V1 -> Ingestion Succeeds
    sig_v1 = generate_origin_signature(raw_bytes, now_ts, key_v1)
    res1 = gateway.ingest_event(payload, raw_bytes=raw_bytes, signature=sig_v1, timestamp=now_ts)
    assert res1["status"] == "accepted"
    assert fake_r.xlen("events:stream:ops05") == 1

    # 2. Secret Rotation: Update gateway secret key to Key V2 (Zero-downtime reconfiguration)
    gateway._secret_key = key_v2

    # 3. Old signature signed with Key V1 must be rejected
    payload_old = {**payload, "event_id": generate_uuidv7()}
    raw_old = json.dumps(payload_old, sort_keys=True).encode("utf-8")
    sig_old = generate_origin_signature(raw_old, now_ts, key_v1)  # signed with retired V1

    with pytest.raises(IngestionAuthenticationError) as exc:
        gateway.ingest_event(payload_old, raw_bytes=raw_old, signature=sig_old, timestamp=now_ts)
    assert "failed" in str(exc.value).lower()
    # Stream length did not change (event was discarded before queue)
    assert fake_r.xlen("events:stream:ops05") == 1

    # 4. New signature signed with Key V2 must succeed
    payload_new = {**payload, "event_id": generate_uuidv7()}
    raw_new = json.dumps(payload_new, sort_keys=True).encode("utf-8")
    sig_new = generate_origin_signature(raw_new, now_ts, key_v2)  # signed with active V2

    res2 = gateway.ingest_event(payload_new, raw_bytes=raw_new, signature=sig_new, timestamp=now_ts)
    assert res2["status"] == "accepted"
    assert fake_r.xlen("events:stream:ops05") == 2


def test_jwt_secret_rotation_lifecycle(monkeypatch):
    """
    OPS-05: Verify JWT signing secret rotation:
    1. Token minted with Secret V1 verifies successfully.
    2. JWT secret is rotated in environment to Secret V2.
    3. Token minted with retired Secret V1 is rejected as untrusted.
    4. Token minted with Secret V2 is accepted.
    """
    jwt_secret_v1 = "super-secure-jwt-secret-version-1-32chars"
    jwt_secret_v2 = "super-secure-jwt-secret-version-2-32chars"

    # Step 1: Mint token under Secret V1
    monkeypatch.setenv("JWT_SECRET", jwt_secret_v1)
    token_v1 = create_access_token({"sub": "analyst_alice", "role": "Analyst"})
    
    # Validates under Secret V1
    claims_v1 = decode_token(token_v1)
    assert claims_v1 is not None
    assert claims_v1["sub"] == "analyst_alice"

    # Step 2: Rotate to Secret V2
    monkeypatch.setenv("JWT_SECRET", jwt_secret_v2)

    # Step 3: Old token signed with Secret V1 must fail decoding
    claims_old = decode_token(token_v1)
    assert claims_old is None, "Token signed with retired JWT secret must be rejected"

    # Step 4: Mint new token under Secret V2 -> must succeed
    token_v2 = create_access_token({"sub": "analyst_alice", "role": "Analyst"})
    claims_new = decode_token(token_v2)
    assert claims_new is not None
    assert claims_new["sub"] == "analyst_alice"
    assert claims_new["role"] == "Analyst"
