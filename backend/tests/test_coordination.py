"""
test_coordination.py — 3-Instance Coordination Integration Test
Week9-Day1 | PhantomNet Project

Tests the full coordination lifecycle:
  - Register 3 honeypot nodes (SSH, HTTP, FTP)
  - Send heartbeats from all nodes
  - Report events and alerts from each node
  - Verify shared threat intelligence
  - Deregister all nodes

Uses FastAPI's TestClient (synchronous) — no running server required.
Run with: pytest backend/tests/test_coordination.py -v
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Bootstrap: ensure project root is importable regardless of run location
# ---------------------------------------------------------------------------
import sys
import os

# Add project root to sys.path so "backend.services.coordinator" is importable
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.services.coordinator import app, state


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_coordinator_state():
    """Reset the global coordinator state before every test for isolation."""
    state.nodes.clear()
    state.events.clear()
    state.alerts.clear()
    state.threat_intel.clear()
    state.heartbeats.clear()
    state.blocked_ips.clear()
    yield
    # Cleanup after test (belt-and-suspenders)
    state.nodes.clear()
    state.events.clear()
    state.alerts.clear()
    state.threat_intel.clear()
    state.heartbeats.clear()
    state.blocked_ips.clear()


@pytest.fixture
def client():
    """FastAPI TestClient — no server process needed."""
    return TestClient(app)


# ---------------------------------------------------------------------------
# Node definitions (3 honeypot instances)
# ---------------------------------------------------------------------------

SSH_NODE = {
    "node_id": "ssh-node-1",
    "host": "127.0.0.1",
    "port": 2222,
    "protocol": "SSH",
    "version": "1.0.0",
    "metadata": {"location": "zone-a"},
}

HTTP_NODE = {
    "node_id": "http-node-2",
    "host": "127.0.0.1",
    "port": 8080,
    "protocol": "HTTP",
    "version": "1.0.0",
    "metadata": {"location": "zone-b"},
}

FTP_NODE = {
    "node_id": "ftp-node-3",
    "host": "127.0.0.1",
    "port": 2121,
    "protocol": "FTP",
    "version": "1.0.0",
    "metadata": {"location": "zone-c"},
}

ALL_NODES = [SSH_NODE, HTTP_NODE, FTP_NODE]

ATTACKER_IPS = {
    "ssh-node-1": "10.0.0.10",
    "http-node-2": "10.0.0.20",
    "ftp-node-3": "10.0.0.30",
}

SHARED_ATTACKER_IP = "192.168.100.99"


# ===========================================================================
# TEST GROUP 1: Health & Root
# ===========================================================================

class TestHealthEndpoints:

    def test_root_returns_running(self, client):
        """Coordinator should report 'running' status at the root endpoint."""
        r = client.get("/")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "running"
        assert data["service"] == "PhantomNet Coordinator"
        assert "registered_nodes" in data
        assert "total_events" in data

    def test_stats_endpoint_empty(self, client):
        """Stats endpoint should return zero counts when no nodes are registered."""
        r = client.get("/stats")
        assert r.status_code == 200
        data = r.json()
        assert data["registered_nodes"] == 0
        assert data["total_events"] == 0
        assert data["total_alerts"] == 0


# ===========================================================================
# TEST GROUP 2: Node Registration
# ===========================================================================

class TestNodeRegistration:

    def test_register_single_node(self, client):
        """A single node can register and its data is returned."""
        r = client.post("/register", json=SSH_NODE)
        assert r.status_code == 201
        data = r.json()
        assert data["success"] is True
        assert data["node"]["node_id"] == SSH_NODE["node_id"]
        assert data["node"]["protocol"] == "SSH"

    def test_register_three_nodes(self, client):
        """All three honeypot nodes can register successfully."""
        for node in ALL_NODES:
            r = client.post("/register", json=node)
            assert r.status_code == 201, f"Registration failed for {node['node_id']}: {r.text}"

        r = client.get("/nodes")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 3

        node_ids = {n["node_id"] for n in data["nodes"]}
        assert node_ids == {"ssh-node-1", "http-node-2", "ftp-node-3"}

    def test_register_updates_existing_node(self, client):
        """Re-registering an existing node updates its info (no duplicate)."""
        client.post("/register", json=SSH_NODE)
        updated = {**SSH_NODE, "version": "2.0.0"}
        r = client.post("/register", json=updated)
        assert r.status_code == 201

        r = client.get("/nodes")
        assert r.json()["total"] == 1  # Still only one node

    def test_nodes_list_empty_initially(self, client):
        """/nodes returns empty list when nothing is registered."""
        r = client.get("/nodes")
        assert r.status_code == 200
        assert r.json()["total"] == 0
        assert r.json()["nodes"] == []


# ===========================================================================
# TEST GROUP 3: Heartbeats
# ===========================================================================

class TestHeartbeats:

    def _register_all(self, client):
        for node in ALL_NODES:
            client.post("/register", json=node)

    def test_heartbeat_from_registered_node(self, client):
        """A registered node can send a heartbeat successfully."""
        self._register_all(client)
        hb = {
            "node_id": "ssh-node-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "active",
            "event_count": 5,
        }
        r = client.post("/heartbeat", json=hb)
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert data["node_id"] == "ssh-node-1"

    def test_heartbeat_from_all_three_nodes(self, client):
        """All 3 nodes can send heartbeats."""
        self._register_all(client)
        for node in ALL_NODES:
            hb = {
                "node_id": node["node_id"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "active",
                "event_count": 10,
            }
            r = client.post("/heartbeat", json=hb)
            assert r.status_code == 200, f"Heartbeat failed for {node['node_id']}"

    def test_heartbeat_unregistered_node_returns_404(self, client):
        """Heartbeat from an unknown node should return 404."""
        hb = {
            "node_id": "ghost-node-99",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "active",
            "event_count": 0,
        }
        r = client.post("/heartbeat", json=hb)
        assert r.status_code == 404

    def test_heartbeat_updates_event_count(self, client):
        """After a heartbeat with event_count=25, the node reflects that count."""
        self._register_all(client)
        hb = {
            "node_id": "http-node-2",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "active",
            "event_count": 25,
        }
        client.post("/heartbeat", json=hb)

        r = client.get("/nodes")
        http_node = next(n for n in r.json()["nodes"] if n["node_id"] == "http-node-2")
        assert http_node["event_count"] == 25


# ===========================================================================
# TEST GROUP 4: Event Reporting
# ===========================================================================

class TestEventReporting:

    def _register_all(self, client):
        for node in ALL_NODES:
            client.post("/register", json=node)

    def test_report_event_from_registered_node(self, client):
        """A registered node can report a capture event."""
        self._register_all(client)
        event = {
            "node_id": "ssh-node-1",
            "src_ip": ATTACKER_IPS["ssh-node-1"],
            "protocol": "SSH",
            "event_type": "login_attempt",
            "details": {"username": "root", "password": "123456"},
        }
        r = client.post("/event", json=event)
        assert r.status_code == 201
        data = r.json()
        assert data["success"] is True
        assert data["total_events"] == 1

    def test_report_events_from_all_three_nodes(self, client):
        """All 3 nodes can report events; total count is correct."""
        self._register_all(client)
        for node in ALL_NODES:
            event = {
                "node_id": node["node_id"],
                "src_ip": ATTACKER_IPS[node["node_id"]],
                "protocol": node["protocol"],
                "event_type": "connection",
                "details": {"banner_grabbed": True},
            }
            r = client.post("/event", json=event)
            assert r.status_code == 201

        r = client.get("/stats")
        assert r.json()["total_events"] == 3

    def test_event_from_unregistered_node_returns_404(self, client):
        """Events from unregistered nodes are rejected."""
        event = {
            "node_id": "unknown-node",
            "src_ip": "1.2.3.4",
            "protocol": "SSH",
            "event_type": "connection",
        }
        r = client.post("/event", json=event)
        assert r.status_code == 404

    def test_same_ip_events_tracked_in_threat_intel(self, client):
        """Multiple events from the same IP accumulate in threat intel."""
        self._register_all(client)
        for _ in range(3):
            event = {
                "node_id": "ssh-node-1",
                "src_ip": SHARED_ATTACKER_IP,
                "protocol": "SSH",
                "event_type": "login_attempt",
            }
            client.post("/event", json=event)

        r = client.get("/threats")
        assert r.status_code == 200
        data = r.json()
        assert data["total_events"] == 3


# ===========================================================================
# TEST GROUP 5: Alert Reporting & Threat Intelligence
# ===========================================================================

class TestAlerts:

    def _register_all(self, client):
        for node in ALL_NODES:
            client.post("/register", json=node)

    def test_high_severity_alert_blocks_ip(self, client):
        """A HIGH alert causes the src_ip to appear in the blocklist."""
        self._register_all(client)
        alert = {
            "node_id": "ssh-node-1",
            "src_ip": SHARED_ATTACKER_IP,
            "severity": "HIGH",
            "description": "Brute force: 500 attempts in 60s",
            "alert_type": "brute_force",
        }
        r = client.post("/alert", json=alert)
        assert r.status_code == 201
        data = r.json()
        assert data["ip_blocked"] is True

        threats = client.get("/threats").json()
        assert SHARED_ATTACKER_IP in threats["blocked_ips"]
        assert SHARED_ATTACKER_IP in threats["high_severity_ips"]

    def test_low_severity_alert_does_not_block_ip(self, client):
        """A LOW alert does NOT add the IP to the blocklist."""
        self._register_all(client)
        alert = {
            "node_id": "http-node-2",
            "src_ip": "172.16.0.5",
            "severity": "LOW",
            "description": "Single port scan detected",
            "alert_type": "scan",
        }
        r = client.post("/alert", json=alert)
        assert r.status_code == 201
        assert r.json()["ip_blocked"] is False

    def test_alerts_from_all_three_nodes(self, client):
        """All 3 nodes can raise alerts; all appear in recent_alerts."""
        self._register_all(client)
        for node in ALL_NODES:
            alert = {
                "node_id": node["node_id"],
                "src_ip": ATTACKER_IPS[node["node_id"]],
                "severity": "HIGH",
                "description": f"Attack on {node['protocol']} honeypot",
                "alert_type": "brute_force",
            }
            r = client.post("/alert", json=alert)
            assert r.status_code == 201

        r = client.get("/threats")
        assert r.status_code == 200
        threats = r.json()
        assert len(threats["recent_alerts"]) == 3
        assert threats["total_events"] == 0  # No events, only alerts
        assert len(threats["high_severity_ips"]) == 3

    def test_critical_alert_blocks_ip(self, client):
        """A CRITICAL alert also adds the IP to the shared blocklist."""
        self._register_all(client)
        alert = {
            "node_id": "ftp-node-3",
            "src_ip": "203.0.113.42",
            "severity": "CRITICAL",
            "description": "Remote code execution attempt",
            "alert_type": "exploit",
        }
        r = client.post("/alert", json=alert)
        assert r.json()["ip_blocked"] is True

    def test_alert_from_unregistered_node_returns_404(self, client):
        """Alerts from unregistered nodes are rejected."""
        alert = {
            "node_id": "intruder-node",
            "src_ip": "1.2.3.4",
            "severity": "HIGH",
            "description": "Fake alert",
            "alert_type": "scan",
        }
        r = client.post("/alert", json=alert)
        assert r.status_code == 404


# ===========================================================================
# TEST GROUP 6: Deregistration
# ===========================================================================

class TestDeregistration:

    def _register_all(self, client):
        for node in ALL_NODES:
            client.post("/register", json=node)

    def test_deregister_single_node(self, client):
        """A registered node can be deregistered."""
        self._register_all(client)
        r = client.post("/deregister", json={"node_id": "ssh-node-1"})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert data["remaining_nodes"] == 2

    def test_deregister_all_nodes_leaves_empty_mesh(self, client):
        """After deregistering all 3 nodes, /nodes returns an empty list."""
        self._register_all(client)
        for node in ALL_NODES:
            r = client.post("/deregister", json={"node_id": node["node_id"]})
            assert r.status_code == 200

        r = client.get("/nodes")
        assert r.json()["total"] == 0
        assert r.json()["nodes"] == []

    def test_deregister_unknown_node_returns_404(self, client):
        """Deregistering a node that never registered returns 404."""
        r = client.post("/deregister", json={"node_id": "ghost-node"})
        assert r.status_code == 404


# ===========================================================================
# TEST GROUP 7: Full End-to-End Coordination Lifecycle
# ===========================================================================

class TestEndToEndCoordination:
    """
    Simulates the complete lifecycle of a 3-node honeypot mesh.
    This is the primary acceptance test for the Week9-Day1 objective.
    """

    def test_full_coordination_lifecycle(self, client):
        """
        Full lifecycle test with 3 nodes:
        1. Register 3 nodes
        2. All send heartbeats
        3. Each reports events
        4. Each raises a HIGH alert
        5. Verify shared threat intel
        6. All deregister
        7. Verify empty mesh
        """
        # --- Step 1: Register all nodes ---
        for node in ALL_NODES:
            r = client.post("/register", json=node)
            assert r.status_code == 201, f"Registration failed: {r.text}"

        r = client.get("/nodes")
        assert r.json()["total"] == 3

        # --- Step 2: Heartbeats from all nodes ---
        for i, node in enumerate(ALL_NODES):
            hb = {
                "node_id": node["node_id"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "active",
                "event_count": i * 10,  # 0, 10, 20
            }
            r = client.post("/heartbeat", json=hb)
            assert r.status_code == 200, f"Heartbeat failed: {node['node_id']}"

        # --- Step 3: Each node reports 2 events ---
        for node in ALL_NODES:
            for j in range(2):
                event = {
                    "node_id": node["node_id"],
                    "src_ip": ATTACKER_IPS[node["node_id"]],
                    "protocol": node["protocol"],
                    "event_type": "login_attempt" if j == 0 else "command",
                    "details": {"attempt": j + 1},
                }
                r = client.post("/event", json=event)
                assert r.status_code == 201

        r = client.get("/stats")
        stats = r.json()
        assert stats["total_events"] == 6  # 3 nodes × 2 events

        # --- Step 4: Each node raises a HIGH alert ---
        for node in ALL_NODES:
            alert = {
                "node_id": node["node_id"],
                "src_ip": ATTACKER_IPS[node["node_id"]],
                "severity": "HIGH",
                "description": f"Brute force on {node['protocol']}",
                "alert_type": "brute_force",
                "details": {"attempts": 100},
            }
            r = client.post("/alert", json=alert)
            assert r.status_code == 201
            assert r.json()["ip_blocked"] is True

        # --- Step 5: Verify shared threat intelligence ---
        r = client.get("/threats")
        assert r.status_code == 200
        threats = r.json()

        # All 3 attacker IPs should be in the blocklist
        blocked = set(threats["blocked_ips"])
        expected_blocked = set(ATTACKER_IPS.values())
        assert expected_blocked.issubset(blocked), (
            f"Expected {expected_blocked} in blocked_ips, got {blocked}"
        )

        # All 3 IPs should be in high_severity_ips
        high_ips = set(threats["high_severity_ips"])
        assert expected_blocked.issubset(high_ips)

        # 3 recent alerts should be present
        assert len(threats["recent_alerts"]) == 3

        # Total event count should be correct
        assert threats["total_events"] == 6

        # --- Step 6: All nodes deregister ---
        for node in ALL_NODES:
            r = client.post("/deregister", json={"node_id": node["node_id"]})
            assert r.status_code == 200

        # --- Step 7: Verify empty mesh ---
        r = client.get("/nodes")
        assert r.json()["total"] == 0
        assert r.json()["nodes"] == []

        # Stats should still show historical data (events/alerts persist)
        r = client.get("/stats")
        stats = r.json()
        assert stats["registered_nodes"] == 0
        assert stats["total_events"] == 6
        assert stats["total_alerts"] == 3
        assert stats["blocked_ips"] == 3
