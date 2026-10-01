import pytest
import asyncio
import threading
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from main import app
from api.topology import topology_manager, push_topology_event_sync
from middleware.auth import create_access_token

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def auth_headers():
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    return {"Cookie": f"phantomnet_access_token={token}"}

def test_topology_unauthenticated(client):
    """Verify that unauthenticated access to /api/v1/topology is rejected with 401."""
    response = client.get("/api/v1/topology")
    assert response.status_code == 401

def test_topology_authenticated(client, auth_headers):
    """Verify that authenticated access to /api/v1/topology returns 200 with truthful port semantics."""
    response = client.get("/api/v1/topology", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    
    # Verify controller semantics
    assert "controller" in data
    assert data["controller"]["name"] == "PHANTOM_OS"
    assert data["controller"]["role"] == "Core Control Plane"
    
    # Verify honeypots semantics and ports
    assert "honeypots" in data
    assert len(data["honeypots"]) == 4
    
    ports_map = {hp.get("protocol") or hp.get("name"): hp for hp in data["honeypots"]}
    assert "SSH" in ports_map
    assert ports_map["SSH"]["external_port"] == 2722
    assert ports_map["SSH"]["internal_port"] == 2222
    assert ports_map["SSH"]["port"] == 2222
    
    assert "HTTP" in ports_map
    assert ports_map["HTTP"]["external_port"] == 8080
    assert ports_map["HTTP"]["internal_port"] == 8080
    
    assert "FTP" in ports_map
    assert ports_map["FTP"]["external_port"] == 2721
    assert ports_map["FTP"]["internal_port"] == 2121
    
    assert "SMTP" in ports_map
    assert ports_map["SMTP"]["external_port"] == 2725
    assert ports_map["SMTP"]["internal_port"] == 2525

def test_honeypots_api_authenticated(client, auth_headers):
    """Verify that /api/honeypots returns 200 with full honeypot nodes."""
    response = client.get("/api/honeypots", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 4

def test_ws_topology_unauthorized_origin(client):
    """Verify that WebSocket handshake from unauthorized Origin is rejected (CSWSH mitigation)."""
    with pytest.raises((WebSocketDisconnect, Exception)):
        with client.websocket_connect(
            "/api/v1/topology/ws",
            headers={"Origin": "http://evil-attacker.com"}
        ) as ws:
            ws.receive_json()

def test_ws_topology_invalid_token(client):
    """Verify that WebSocket handshake with invalid credentials is closed with 4001."""
    with pytest.raises((WebSocketDisconnect, Exception)):
        with client.websocket_connect("/api/v1/topology/ws?token=invalid_forged_token") as ws:
            ws.receive_json()

def test_ws_topology_authenticated_init(client):
    """Verify that WebSocket with cookie and valid Origin connects and receives INIT payload."""
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    client.cookies.set("phantomnet_access_token", token)
    try:
        with client.websocket_connect(
            "/api/v1/topology/ws",
            headers={"Origin": "http://localhost:3000"}
        ) as websocket:
            data = websocket.receive_json()
            assert data["type"] == "INIT"
            assert "payload" in data
            assert "nodes" in data["payload"]
            assert "edges" in data["payload"]
            assert len(data["payload"]["nodes"]) >= 5
            assert len(data["payload"]["edges"]) >= 4
    finally:
        client.cookies.clear()

def test_push_topology_event_sync_thread_safety():
    """Verify NT-DEF-02 fix: push_topology_event_sync can be safely called from worker threads."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    topology_manager.set_loop(loop)
    
    test_event = {
        "event_id": "test_evt_001",
        "attacker_ip": "198.51.100.42",
        "target_service": "SSH",
        "severity": "HIGH",
        "timestamp": "2026-09-30T17:00:00Z"
    }
    
    exception_caught = None
    
    def worker_thread():
        nonlocal exception_caught
        try:
            push_topology_event_sync("ATTACK_EVENT", test_event)
        except Exception as e:
            exception_caught = e
            
    thread = threading.Thread(target=worker_thread)
    thread.start()
    thread.join()
    
    assert exception_caught is None, f"Thread-safe event push failed: {exception_caught}"
