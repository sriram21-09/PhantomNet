"""
tests/api/test_active_defense.py
-------------------------------
Verifies Active Defense guardrails according to SEC-07:
- Endpoint /active-defense/block/{ip} requires Admin role.
- Requires valid step-up token (X-Step-Up-Token).
- Forbids blocking loopback, RFC 1918 private addresses, and reserved subnets.
- Emits cryptographic audit log entry.
"""
import pytest
from fastapi.testclient import TestClient
from database.models import AuditLog


def test_block_unauthenticated_returns_401(client: TestClient):
    """Unauthenticated access to active defense is denied."""
    response = client.post("/active-defense/block/198.51.100.42")
    assert response.status_code == 401


def test_block_analyst_returns_403(client: TestClient, analyst_headers: dict, step_up_token: str):
    """Analyst cannot execute active defense blocks (requires Admin)."""
    headers = dict(analyst_headers)
    headers["X-Step-Up-Token"] = step_up_token
    response = client.post("/active-defense/block/198.51.100.42", headers=headers)
    assert response.status_code == 403


def test_block_admin_without_step_up_token_returns_forbidden(client: TestClient, admin_headers: dict):
    """Admin cannot execute active defense blocks without an active step-up token."""
    response = client.post("/active-defense/block/198.51.100.42", headers=admin_headers)
    assert response.status_code in [401, 403]
    assert "step-up" in response.json()["detail"].lower()


def test_block_private_ip_prevented(client: TestClient, admin_headers: dict, step_up_token: str):
    """Blocking loopback or RFC 1918 private IPs is rejected with 400."""
    headers = dict(admin_headers)
    headers["X-Step-Up-Token"] = step_up_token

    for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1"]:
        response = client.post(f"/active-defense/block/{ip}", headers=headers)
        assert response.status_code == 400
        assert "private" in response.json()["detail"].lower() or "loopback" in response.json()["detail"].lower()


def test_block_valid_ip_succeeds_and_creates_audit_log(
    client: TestClient, admin_headers: dict, step_up_token: str, db_session, monkeypatch
):
    """Admin with valid step-up token can block public IP, creating an immutable audit log."""
    from services.firewall import FirewallService
    monkeypatch.setattr(
        FirewallService,
        "block_ip",
        lambda ip: {"status": "success", "message": f"Target {ip} successfully neutralized."}
    )

    headers = dict(admin_headers)
    headers["X-Step-Up-Token"] = step_up_token

    target_ip = "93.184.216.34"
    response = client.post(f"/active-defense/block/{target_ip}", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Verify audit log recorded in DB
    log = db_session.query(AuditLog).filter(
        AuditLog.action == "BLOCK_IP",
        AuditLog.target == target_ip
    ).first()
    assert log is not None
    assert log.actor == "admin_user"
    assert log.record_hash is not None
