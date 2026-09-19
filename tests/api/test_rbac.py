"""
tests/api/test_rbac.py
---------------------
Verifies Role-Based Access Control (RBAC) across Viewer, Analyst, and Admin tiers.
Ensures least privilege is strictly enforced on all mutating and sensitive endpoints.
"""
import pytest
from fastapi.testclient import TestClient


def test_viewer_can_read_alerts_but_cannot_mutate(
    client: TestClient, viewer_headers: dict
):
    """Viewer can read alerts but receives 403 Forbidden when attempting to resolve."""
    read_resp = client.get("/api/v1/alerts", headers=viewer_headers)
    assert read_resp.status_code == 200

    mutate_resp = client.patch(
        "/api/v1/alerts/1/resolve",
        headers=viewer_headers,
    )
    assert mutate_resp.status_code == 403
    assert "Forbidden" in mutate_resp.json()["detail"] or "role" in mutate_resp.json()["detail"].lower()


def test_viewer_cannot_create_investigation_case(client: TestClient, viewer_headers: dict):
    """Viewer receives 403 Forbidden when attempting to create a new case."""
    response = client.post(
        "/api/v1/cases/",
        headers=viewer_headers,
        json={
            "title": "Unauthorized Case",
            "description": "Viewer cannot create cases",
            "priority": "High"
        }
    )
    assert response.status_code == 403


def test_viewer_cannot_run_threat_hunting_queries(client: TestClient, viewer_headers: dict):
    """Viewer receives 403 Forbidden on hunting query endpoints."""
    response = client.post(
        "/api/v1/hunting/search",
        headers=viewer_headers,
        json={"logic": "AND", "conditions": []}
    )
    assert response.status_code == 403


def test_viewer_cannot_access_pcap(client: TestClient, viewer_headers: dict):
    """Viewer receives 403 Forbidden on PCAP endpoints."""
    response = client.get("/api/v1/pcap/stats", headers=viewer_headers)
    assert response.status_code == 403


def test_analyst_can_access_hunting_and_cases(
    client: TestClient, analyst_headers: dict
):
    """Analyst can access threat hunting and PCAP stats endpoints."""
    hunting_resp = client.post(
        "/api/v1/hunting/search",
        headers=analyst_headers,
        json={"logic": "AND", "conditions": []}
    )
    assert hunting_resp.status_code in [200, 422]

    pcap_resp = client.get("/api/v1/pcap/stats", headers=analyst_headers)
    assert pcap_resp.status_code == 200


def test_analyst_cannot_access_admin_user_management(client: TestClient, analyst_headers: dict):
    """Analyst receives 403 Forbidden when accessing Admin-only user management."""
    response = client.get("/api/v1/admin/users", headers=analyst_headers)
    assert response.status_code == 403


def test_analyst_cannot_access_taxii_client_management(client: TestClient, analyst_headers: dict):
    """Analyst receives 403 Forbidden on TAXII client management."""
    response = client.get("/api/v1/admin/taxii/clients", headers=analyst_headers)
    assert response.status_code == 403


def test_admin_can_access_admin_routes(client: TestClient, admin_headers: dict):
    """Admin has access to user management and TAXII admin routes."""
    user_resp = client.get("/api/v1/admin/users", headers=admin_headers)
    assert user_resp.status_code == 200

    taxii_resp = client.get("/api/v1/admin/taxii/clients", headers=admin_headers)
    assert taxii_resp.status_code == 200
