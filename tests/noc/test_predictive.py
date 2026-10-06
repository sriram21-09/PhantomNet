"""
tests/noc/test_predictive.py
----------------------------
Verifies authentication, payload veracity, and graceful degradation for predictive endpoints:
- /api/v1/predictive/forecast
- /api/v1/predictive/risk-score
- /api/v1/predictive/next-attack
"""
import pytest
from database.models import PacketLog


def test_predictive_authentication_rejected(client):
    """Verify unauthenticated requests to predictive endpoints return 401."""
    endpoints = [
        "/api/v1/predictive/forecast",
        "/api/v1/predictive/risk-score",
        "/api/v1/predictive/next-attack",
    ]
    for ep in endpoints:
        res = client.get(ep)
        assert res.status_code == 401, f"Endpoint {ep} must reject unauthenticated requests"


def test_predictive_authenticated_cookie(client, auth_cookies, seed_packets):
    """Verify requests authenticated via cookie return 200."""
    endpoints = [
        "/api/v1/predictive/forecast",
        "/api/v1/predictive/risk-score",
        "/api/v1/predictive/next-attack",
    ]
    for ep in endpoints:
        res = client.get(ep, cookies=auth_cookies)
        assert res.status_code == 200, f"Endpoint {ep} failed with status {res.status_code}"


def test_predictive_forecast_truthful_model_claim(client, auth_cookies, seed_packets):
    """Verify forecast endpoint does NOT claim an LSTM model."""
    res = client.get("/api/v1/predictive/forecast", cookies=auth_cookies)
    assert res.status_code == 200
    data = res.json()
    assert "model" in data
    assert "LSTM" not in data["model"], "Must not claim false LSTM model"
    assert "Statistical" in data["model"]
    assert "historical" in data
    assert "forecast" in data
    assert "trend" in data
    assert data["trend"] in ("RISING", "FALLING", "STABLE")


def test_predictive_risk_score_scale(client, auth_cookies, seed_packets):
    """Verify risk-score returns canonical 0-100 percentage and canonical level."""
    res = client.get("/api/v1/predictive/risk-score", cookies=auth_cookies)
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
    assert "risk_level" in data
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_predictive_empty_data_graceful(client, auth_cookies, TestingSessionLocal):
    """Verify that when no packet logs exist, next-attack does not invent fake predictions."""
    session = TestingSessionLocal()
    session.query(PacketLog).delete()
    session.commit()
    session.close()

    res = client.get("/api/v1/predictive/next-attack", cookies=auth_cookies)
    assert res.status_code == 200
    data = res.json()
    assert data.get("has_data") is False
    assert data.get("target") == "Insufficient data"
    assert data.get("confidence") is None
    assert data.get("estimated_minutes") is None
