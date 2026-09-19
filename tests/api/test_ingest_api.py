"""
Test Suite: Ingestion Gateway API Router Endpoints
Validates:
1. /api/v1/ingest/event with HMAC origin signature returns HTTP 202 Accepted.
2. /api/v1/ingest/event with invalid signature returns HTTP 401 Unauthorized in production mode.
3. /api/v1/ingest/batch handles array of envelopes.
4. /api/v1/ingest/health reports queue depth.
5. Backpressure enforcement returns HTTP 429 Too Many Requests with Retry-After header.
"""
import os
import sys
import json
import pytest

os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "a" * 32
os.environ["HONEYPOT_SECRET_KEY"] = "b" * 32

import fakeredis
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from main import app
from services.ingestion_gateway import IngestionGateway
from api.ingest import set_ingestion_gateway
from services.origin_auth import generate_origin_signature, get_honeypot_secret_key
from schemas.event_envelope import generate_uuidv7


@pytest.fixture
def fake_redis_gateway():
    r = fakeredis.FakeRedis()
    gw = IngestionGateway(
        redis_client=r,
        stream_key="events:test_stream",
        max_stream_len=10,  # Small limit to test backpressure
        secret_key="b" * 32,
    )
    set_ingestion_gateway(gw)
    return gw, r


@pytest.fixture
def client():
    return TestClient(app)


def test_ingest_event_with_valid_signature_succeeds(client, fake_redis_gateway):
    gw, r = fake_redis_gateway
    event_payload = {
        "event_id": generate_uuidv7(),
        "honeypot_id": "ssh-node-01",
        "event_type": "SSH",
        "src_ip": "198.51.100.12",
        "dst_port": 2222,
        "protocol": "TCP",
    }
    body_bytes = json.dumps(event_payload, sort_keys=True).encode("utf-8")
    import time
    ts = int(time.time())
    sig = generate_origin_signature(body_bytes, ts, secret_key="b" * 32)

    headers = {
        "Content-Type": "application/json",
        "X-Honeypot-Signature": sig,
        "X-Honeypot-Timestamp": str(ts),
        "X-Honeypot-ID": "ssh-node-01",
    }

    response = client.post("/api/v1/ingest/event", content=body_bytes, headers=headers)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert data["event_id"] == event_payload["event_id"]
    assert r.xlen("events:test_stream") == 1


def test_ingest_event_invalid_signature_rejected(client, fake_redis_gateway, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    event_payload = {
        "event_id": generate_uuidv7(),
        "honeypot_id": "ssh-node-01",
        "event_type": "SSH",
        "src_ip": "198.51.100.12",
    }
    body_bytes = json.dumps(event_payload, sort_keys=True).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "X-Honeypot-Signature": "invalid-tampered-signature",
        "X-Honeypot-Timestamp": "1600000000",
    }

    response = client.post("/api/v1/ingest/event", content=body_bytes, headers=headers)
    assert response.status_code == 401


def test_ingest_batch_succeeds(client, fake_redis_gateway):
    gw, r = fake_redis_gateway
    batch = [
        {
            "event_id": generate_uuidv7(),
            "honeypot_id": f"http-{i}",
            "event_type": "HTTP",
            "src_ip": f"198.51.100.{i + 1}",
            "dst_port": 8080,
        }
        for i in range(3)
    ]
    body_bytes = json.dumps(batch, sort_keys=True).encode("utf-8")
    import time
    ts = int(time.time())
    sig = generate_origin_signature(body_bytes, ts, secret_key="b" * 32)

    headers = {
        "Content-Type": "application/json",
        "X-Honeypot-Signature": sig,
        "X-Honeypot-Timestamp": str(ts),
    }

    response = client.post("/api/v1/ingest/batch", content=body_bytes, headers=headers)
    assert response.status_code == 202
    res = response.json()
    assert res["accepted_count"] == 3


def test_ingest_backpressure_enforcement_returns_429(client, fake_redis_gateway):
    gw, r = fake_redis_gateway
    # The max_stream_len is set to 10
    # Add 10 items directly to saturate stream
    for i in range(10):
        r.xadd("events:test_stream", {"dummy": f"{i}"})

    event_payload = {
        "event_id": generate_uuidv7(),
        "honeypot_id": "ssh-node-01",
        "event_type": "SSH",
        "src_ip": "198.51.100.99",
    }
    body_bytes = json.dumps(event_payload, sort_keys=True).encode("utf-8")

    response = client.post("/api/v1/ingest/event", content=body_bytes, headers={"Content-Type": "application/json"})
    assert response.status_code == 429
    assert "Retry-After" in response.headers
    assert response.headers["Retry-After"] == "5"


def test_ingest_health_endpoint(client, fake_redis_gateway):
    gw, r = fake_redis_gateway
    response = client.get("/api/v1/ingest/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "queue_depth" in data
    assert data["max_queue_depth"] == 10
