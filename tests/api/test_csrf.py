"""
tests/api/test_csrf.py
---------------------
Verifies CSRF mitigation according to SEC-03.
Mutating requests using ambient cookies must present a custom anti-CSRF header
(X-CSRF-Token or X-Requested-With) and a permitted Origin header.
Direct Bearer-token requests are exempt as they are not vulnerable to browser ambient credential replay.
"""
import pytest
from fastapi.testclient import TestClient


def test_safe_methods_exempt_from_csrf(client: TestClient, admin_token: str):
    """GET requests with cookies do not require CSRF headers."""
    client.cookies.set("phantomnet_access_token", admin_token)
    response = client.get("/api/v1/admin/users")
    assert response.status_code == 200
    client.cookies.clear()


def test_bearer_token_mutations_exempt_from_csrf(client: TestClient, admin_token: str):
    """Mutations authenticated via Bearer token (no cookies) do not require CSRF token."""
    response = client.post(
        "/api/v1/cases/",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "Bearer Auth Case",
            "description": "Valid investigation case",
            "priority": "Medium"
        }
    )
    # 200 or 201 indicates CSRF did not block the request
    assert response.status_code in [200, 201]


def test_cookie_mutations_without_csrf_header_blocked(client: TestClient, admin_token: str):
    """Mutations carrying cookie credentials without custom anti-CSRF headers are blocked with 403."""
    client.cookies.set("phantomnet_access_token", admin_token)
    response = client.post(
        "/api/v1/cases/",
        json={
            "title": "CSRF Attack Attempt",
            "description": "Attempted CSRF attack payload",
            "priority": "High"
        }
    )
    assert response.status_code == 403
    data = response.json()
    assert "CSRF" in data["detail"] or "anti-CSRF" in data["detail"]
    client.cookies.clear()


def test_cookie_mutations_with_csrf_header_allowed(client: TestClient, admin_token: str):
    """Mutations carrying cookie credentials along with X-CSRF-Token header are permitted."""
    client.cookies.set("phantomnet_access_token", admin_token)
    response = client.post(
        "/api/v1/cases/",
        headers={
            "X-CSRF-Token": "test-csrf-token-12345",
            "Origin": "http://localhost:3000"
        },
        json={
            "title": "Legitimate Cookie Post",
            "description": "Valid authenticated request with CSRF token",
            "priority": "Low"
        }
    )
    assert response.status_code in [200, 201]
    client.cookies.clear()


def test_disallowed_origin_header_blocked(client: TestClient, admin_token: str):
    """Mutations originating from an untrusted origin are blocked with 403."""
    client.cookies.set("phantomnet_access_token", admin_token)
    response = client.post(
        "/api/v1/cases/",
        headers={
            "X-CSRF-Token": "test-csrf-token-12345",
            "Origin": "http://attacker-controlled-domain.xyz"
        },
        json={
            "title": "Malicious Origin",
            "description": "Disallowed origin test",
            "priority": "Low"
        }
    )
    assert response.status_code == 403
    assert "origin" in response.json()["detail"].lower()
    client.cookies.clear()
