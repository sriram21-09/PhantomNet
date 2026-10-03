"""
backend/tests/test_sentinel_timeline.py
----------------------------------------
Unit tests for Sentinel Campaign Timeline Time-Series API endpoint:
  GET /api/sentinel/campaigns/{campaign_id}/timeline
"""

import pytest
from fastapi.testclient import TestClient
from main import app
from middleware.auth import get_current_user
from database.models import User

client = TestClient(app)

@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: User(id=1, username="testadmin", role="admin", status="active")
    yield
    app.dependency_overrides.pop(get_current_user, None)


def test_get_campaign_timeline_success():
    """Test retrieving campaign timeline time-series data."""
    response = client.get("/api/sentinel/campaigns/CMP-2026-001/timeline")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert data["campaign_id"] == "CMP-2026-001"
    assert "total_events" in data
    assert "peak_density" in data
    assert "spike_count" in data
    assert "anomaly_count" in data
    assert isinstance(data["timeline"], list)
    assert len(data["timeline"]) > 0

    # Verify time series item schema
    item = data["timeline"][0]
    assert "timestamp" in item
    assert "count" in item
    assert "density" in item
    assert "is_spike" in item
    assert "is_anomaly" in item


def test_get_campaign_timeline_spikes_and_anomalies():
    """Test that campaign timeline identifies spikes and anomaly timestamps."""
    response = client.get("/api/sentinel/campaigns/CMP-TEST-SPIKES/timeline")
    assert response.status_code == 200
    data = response.json()

    timeline = data["timeline"]
    spikes = [pt for pt in timeline if pt.get("is_spike")]
    anomalies = [pt for pt in timeline if pt.get("is_anomaly")]

    assert len(spikes) >= 1, "Expected at least one attack spike in campaign timeline"
    assert len(anomalies) >= 1, "Expected at least one anomaly timestamp in campaign timeline"

    spike = spikes[0]
    assert spike["threat_level"] in ("critical", "high")
    assert spike["anomaly_type"] is not None
