"""
tests/api/test_token_lifecycle.py
--------------------------------
Verifies refresh token rotation, token family grouping, and automatic replay/reuse detection.
SEC-04: If an already-rotated refresh token is presented again (replay attack),
the entire token family must be revoked immediately.
"""
import hashlib
import pytest
from fastapi.testclient import TestClient
from database.models import RefreshToken


def test_refresh_token_rotation(client: TestClient, db_session):
    """Calling /api/v1/admin/refresh issues new tokens and marks the parent as used/revoked."""
    # 1. Login to obtain initial tokens
    login_resp = client.post(
        "/api/v1/admin/login",
        json={"username": "admin_user", "password": "AdminPass123!"}
    )
    assert login_resp.status_code == 200
    init_data = login_resp.json()
    token_1 = init_data["refresh_token"]

    # 2. Use token_1 to refresh
    refresh_resp = client.post(
        "/api/v1/admin/refresh",
        json={"refresh_token": token_1}
    )
    assert refresh_resp.status_code == 200
    refreshed_data = refresh_resp.json()
    token_2 = refreshed_data["refresh_token"]
    assert token_2 != token_1
    assert "access_token" in refreshed_data

    # 3. Verify token_1 is marked rotated/revoked in DB
    token_1_hash = hashlib.sha256(token_1.encode("utf-8")).hexdigest()
    db_token_1 = db_session.query(RefreshToken).filter(RefreshToken.token_hash == token_1_hash).first()
    assert db_token_1 is not None
    assert db_token_1.rotated_at is not None or db_token_1.revoked_at is not None


def test_token_family_reuse_detection_revokes_entire_family(client: TestClient, db_session):
    """
    CRITICAL SECURITY TEST:
    If an attacker replays token_1 after it was already rotated to token_2,
    the server must detect token reuse, reject the request with 401,
    and REVOKE the entire token family (including token_2).
    """
    # 1. Initial Login
    login_resp = client.post(
        "/api/v1/admin/login",
        json={"username": "admin_user", "password": "AdminPass123!"}
    )
    assert login_resp.status_code == 200
    token_1 = login_resp.json()["refresh_token"]

    # 2. Legitimate user rotates token_1 -> token_2
    refresh_1 = client.post(
        "/api/v1/admin/refresh",
        json={"refresh_token": token_1}
    )
    assert refresh_1.status_code == 200
    token_2 = refresh_1.json()["refresh_token"]

    # 3. Attacker replays token_1
    replay_resp = client.post(
        "/api/v1/admin/refresh",
        json={"refresh_token": token_1}
    )
    assert replay_resp.status_code == 401
    assert "reuse" in replay_resp.json()["detail"].lower() or "revoked" in replay_resp.json()["detail"].lower()

    # 4. Legitimate user now tries to use token_2 (which should have been revoked by the breach detection)
    legit_next_attempt = client.post(
        "/api/v1/admin/refresh",
        json={"refresh_token": token_2}
    )
    assert legit_next_attempt.status_code == 401
    assert "revoked" in legit_next_attempt.json()["detail"].lower()


def test_logout_revokes_token_family(client: TestClient, db_session):
    """Logging out revokes the token and invalidates the session."""
    login_resp = client.post(
        "/api/v1/admin/login",
        json={"username": "admin_user", "password": "AdminPass123!"}
    )
    assert login_resp.status_code == 200
    refresh_token = login_resp.json()["refresh_token"]

    logout_resp = client.post(
        "/api/v1/admin/logout",
        json={"refresh_token": refresh_token}
    )
    assert logout_resp.status_code == 200

    # Next attempt with the token fails
    subsequent_resp = client.post(
        "/api/v1/admin/refresh",
        json={"refresh_token": refresh_token}
    )
    assert subsequent_resp.status_code == 401
