"""
tests/api/test_auth.py
---------------------
Verifies that all API endpoints enforce authentication and reject unauthenticated requests.
Validates both Bearer authorization headers and HttpOnly session cookies.
"""
import pytest
from fastapi.testclient import TestClient


PROTECTED_GET_ENDPOINTS = [
    "/api/events",
    "/api/v1/alerts",
    "/api/v1/cases",
    "/api/v1/reports/generate",
    "/api/honeypots",
    "/api/v1/predictive/forecast",
    "/api/threat-metrics",
    "/api/cache/stats",
]


@pytest.mark.parametrize("endpoint", PROTECTED_GET_ENDPOINTS)
def test_unauthenticated_requests_return_401(client: TestClient, endpoint: str):
    """Ensure any request without credentials receives HTTP 401 Unauthorized."""
    response = client.get(endpoint)
    assert response.status_code == 401, f"Endpoint {endpoint} was not protected (returned {response.status_code})"
    data = response.json()
    assert "detail" in data
    assert "Not authenticated" in data["detail"] or "Invalid" in data["detail"] or "Missing" in data["detail"]


def test_authenticated_bearer_token_access(client: TestClient, viewer_headers: dict):
    """Ensure valid Bearer token grants access to protected endpoints."""
    response = client.get("/api/v1/alerts", headers=viewer_headers)
    assert response.status_code == 200


def test_authenticated_cookie_access(client: TestClient, viewer_token: str):
    """Ensure valid HttpOnly access_token cookie grants access to protected endpoints."""
    client.cookies.set("phantomnet_access_token", viewer_token)
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    client.cookies.clear()


def test_invalid_bearer_token_returns_401(client: TestClient):
    """Ensure forged or invalid Bearer tokens are rejected."""
    headers = {"Authorization": "Bearer invalid.token.value"}
    response = client.get("/api/v1/alerts", headers=headers)
    assert response.status_code == 401


def test_tampered_token_signature_returns_401(client: TestClient, viewer_token: str):
    """Ensure tokens with modified signatures are rejected."""
    tampered = viewer_token[:-5] + "XXXXX"
    headers = {"Authorization": f"Bearer {tampered}"}
    response = client.get("/api/v1/alerts", headers=headers)
    assert response.status_code == 401


def test_login_success_sets_cookie_and_returns_tokens(client: TestClient):
    """Ensure /api/v1/admin/login returns both access and refresh tokens and sets cookie."""
    response = client.post(
        "/api/v1/admin/login",
        json={"username": "admin_user", "password": "AdminPass123!"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert "phantomnet_access_token" in response.cookies or "access_token" in response.cookies


def test_login_invalid_credentials_returns_401(client: TestClient):
    """Ensure incorrect credentials receive 401."""
    response = client.post(
        "/api/v1/admin/login",
        json={"username": "admin_user", "password": "WrongPassword"}
    )
    assert response.status_code == 401
