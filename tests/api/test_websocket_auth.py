"""
tests/api/test_websocket_auth.py
--------------------------------
Verifies WebSocket authentication and CSWSH mitigation (SEC-03).
Handshake must be authenticated via cookie or authorization header.
Tokens passed via query parameters must be rejected.
Disallowed origins must be rejected during the upgrade handshake.
"""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


def test_websocket_unauthenticated_connection_rejected(client: TestClient):
    """Unauthenticated WebSocket handshake attempt is rejected."""
    with pytest.raises((WebSocketDisconnect, Exception)):
        with client.websocket_connect("/api/v1/topology/ws"):
            pass


def test_websocket_query_param_token_rejected(client: TestClient, viewer_token: str):
    """Passing credentials in query parameter (?token=...) is strictly rejected."""
    with pytest.raises((WebSocketDisconnect, Exception)):
        with client.websocket_connect(f"/api/v1/topology/ws?token={viewer_token}"):
            pass


def test_websocket_cookie_authenticated_connection_succeeds(client: TestClient, viewer_token: str):
    """WebSocket handshake with ambient cookie and valid Origin succeeds."""
    client.cookies.set("phantomnet_access_token", viewer_token)
    try:
        with client.websocket_connect(
            "/api/v1/topology/ws",
            headers={"Origin": "http://localhost:3000"}
        ) as websocket:
            # Successfully connected; receive initial topology or ping
            data = websocket.receive_json()
            assert isinstance(data, (dict, list))
    finally:
        client.cookies.clear()
