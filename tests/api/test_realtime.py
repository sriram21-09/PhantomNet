import os
import sys
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.main import app
from backend.middleware.auth import create_access_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def viewer_token():
    return create_access_token(data={"sub": "viewer_user", "role": "Viewer"})


def test_realtime_ws_unauthenticated_rejected(client: TestClient):
    """RT-01: Unauthenticated WebSocket handshake is rejected."""
    with pytest.raises((WebSocketDisconnect, Exception)):
        with client.websocket_connect("/api/v1/realtime/ws"):
            pass


def test_realtime_ws_query_param_token_rejected(client: TestClient, viewer_token: str):
    """RT-01: Passing credentials in query parameter (?token=...) is rejected."""
    with pytest.raises((WebSocketDisconnect, Exception)):
        with client.websocket_connect(f"/api/v1/realtime/ws?token={viewer_token}"):
            pass


def test_realtime_ws_unauthorized_origin_rejected(client: TestClient, viewer_token: str):
    """RT-01: Disallowed Origin is rejected to prevent CSWSH attacks."""
    client.cookies.set("phantomnet_access_token", viewer_token)
    try:
        with pytest.raises((WebSocketDisconnect, Exception)):
            with client.websocket_connect(
                "/api/v1/realtime/ws",
                headers={"Origin": "https://attacker.evil.com"}
            ):
                pass
    finally:
        client.cookies.clear()


def test_realtime_ws_authenticated_connection_succeeds(client: TestClient, viewer_token: str):
    """RT-01: Authenticated handshake with allowed Origin succeeds."""
    client.cookies.set("phantomnet_access_token", viewer_token)
    try:
        with client.websocket_connect(
            "/api/v1/realtime/ws",
            headers={"Origin": "http://localhost:3000"}
        ) as websocket:
            data = websocket.receive_json()
            assert data["type"] == "connected"
    finally:
        client.cookies.clear()
