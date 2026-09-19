import os
import sys
import pytest
from starlette.testclient import TestClient
from unittest.mock import patch, MagicMock

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.main import app
from backend.services.telemetry import telemetry_service


@pytest.fixture
def client():
    return TestClient(app)


def test_liveness_probe_returns_200(client):
    """OBS-01: Liveness probe must return 200 OK and uptime."""
    res = client.get("/health/live")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "alive"
    assert "timestamp" in data
    assert "uptime_seconds" in data
    assert data["uptime_seconds"] >= 0


def test_readiness_probe_healthy_returns_200(client):
    """OBS-01: Readiness probe returns 200 OK with dependency checks when DB is UP."""
    res = client.get("/health/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["ready", "degraded"]
    assert data["ready"] is True
    assert "postgres" in data["checks"]
    assert data["checks"]["postgres"] == "healthy"


def test_startup_probe_returns_200(client):
    """OBS-01: Startup probe verifies tables and schema accessibility."""
    res = client.get("/health/startup")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "started"
    assert data["database_initialized"] is True


def test_readiness_probe_database_failure_returns_503(client):
    """OBS-01: Readiness probe returns 503 when core PostgreSQL dependency is unreachable."""
    try:
        from database.database import get_db
    except ImportError:
        from backend.database.database import get_db

    def mock_broken_db():
        mock_session = MagicMock()
        mock_session.execute.side_effect = Exception("PostgreSQL connection refused")
        yield mock_session

    app.dependency_overrides[get_db] = mock_broken_db
    try:
        res = client.get("/health/ready")
        assert res.status_code == 503
        data = res.json()
        assert data["status"] == "unhealthy"
        assert data["ready"] is False
        assert "unhealthy" in data["checks"]["postgres"]
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_prometheus_metrics_endpoint(client):
    """OBS-03: Exposes standard Prometheus text metrics."""
    # Increment some metrics first
    telemetry_service.record_ingest("honeypot_test", "ssh_attempt", "accepted", 0.015)
    telemetry_service.set_stream_depth("events:stream", 42)

    res = client.get("/metrics")
    assert res.status_code == 200
    assert "text/plain" in res.headers.get("content-type", "")

    body = res.text
    assert "phantomnet_events_total" in body
    assert "phantomnet_stream_queue_depth" in body
    assert "phantomnet_ingestion_latency_seconds" in body
    assert "phantomnet_degraded_mode" in body
