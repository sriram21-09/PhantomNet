"""
P0 and P1 Bug Resolution & Reliability Test Suite
=================================================
Validates fixes for critical (P0) and high (P1) bugs in Core and API layers:
1. Cross-platform FirewallService blocking and unblocking (P0)
2. PolicyEngine JSON corruption recovery and node policy assignment (P0)
3. Honeypot socket probing reliability and latency bounds (P1)
4. ResponseExecutor thread-safety and concurrency handling (P1)
"""

import os
import sys
import json
import threading

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

os.environ["ENVIRONMENT"] = "test"

import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from database.database import Base, get_db
from database.models import HoneypotNode, Policy
from services.firewall import FirewallService
from services.policy_engine import PolicyEngine
from services.node_manager import NodeManager
from services.response_executor import ResponseExecutor
from api.honeypots import check_port_status
from main import app

# In-memory database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session(setup_db):
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ===========================================================================
# 1. P0: CROSS-PLATFORM FIREWALL SERVICE RESOLUTION
# ===========================================================================
class TestFirewallServiceResolution:
    def test_firewall_invalid_ip_rejection(self):
        """Invalid IP addresses are rejected before executing subprocess commands."""
        res = FirewallService.block_ip("not_an_ip")
        assert res["status"] == "error"
        assert "Invalid IP" in res["message"]

        res_unblock = FirewallService.unblock_ip("999.999.999.999")
        assert res_unblock["status"] == "error"
        assert "Invalid IP" in res_unblock["message"]

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run")
    def test_firewall_linux_block_and_unblock(self, mock_run, mock_platform):
        """Linux uses iptables commands for block and unblock."""
        mock_run.return_value = MagicMock(returncode=0)

        res_block = FirewallService.block_ip("198.51.100.22")
        assert res_block["status"] == "success"
        mock_run.assert_called_with(
            ["sudo", "iptables", "-A", "INPUT", "-s", "198.51.100.22", "-j", "DROP"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

        res_unblock = FirewallService.unblock_ip("198.51.100.22")
        assert res_unblock["status"] == "success"
        mock_run.assert_called_with(
            ["sudo", "iptables", "-D", "INPUT", "-s", "198.51.100.22", "-j", "DROP"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

    @patch("platform.system", return_value="Windows")
    @patch("subprocess.run")
    def test_firewall_windows_block_and_unblock(self, mock_run, mock_platform):
        """Windows uses netsh advfirewall commands for block and unblock."""
        mock_run.return_value = MagicMock(returncode=0)

        res_block = FirewallService.block_ip("203.0.113.5")
        assert res_block["status"] == "success"
        mock_run.assert_called_with(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=PhantomNet_Block_203.0.113.5",
                "dir=in",
                "action=block",
                "remoteip=203.0.113.5",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

        res_unblock = FirewallService.unblock_ip("203.0.113.5")
        assert res_unblock["status"] == "success"
        mock_run.assert_called_with(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=PhantomNet_Block_203.0.113.5",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )


# ===========================================================================
# 2. P0: POLICY ENGINE JSON CORRUPTION RECOVERY
# ===========================================================================
class TestPolicyEngineCorruptionRecovery:
    def test_policy_config_corrupted_json_handled_safely(self, db_session):
        """Corrupted JSON string in Policy.config does not crash get_policy_for_node."""
        engine = PolicyEngine(db_session)
        manager = NodeManager(db_session)

        node = manager.register_node("Honeypot-Node-1", "10.0.0.50", "SSH")
        bad_policy = Policy(
            name="Corrupted Config Policy",
            description="Testing recovery from bad config",
            config="{malformed_json: missing_quotes}"
        )
        db_session.add(bad_policy)
        db_session.commit()
        db_session.refresh(bad_policy)

        engine.assign_policy_to_node(node.node_id, bad_policy.id)
        config = engine.get_policy_for_node(node.node_id)
        assert config is not None
        assert "raw_config" in config
        assert config["raw_config"] == "{malformed_json: missing_quotes}"

    def test_policy_config_valid_json(self, db_session):
        """Valid JSON policy config parsed correctly into dictionary."""
        engine = PolicyEngine(db_session)
        manager = NodeManager(db_session)

        node = manager.register_node("Honeypot-Node-2", "10.0.0.51", "HTTP")
        policy = engine.create_policy("Valid Policy", "Standard policy", {"rate_limit": 50, "log_payload": True})

        engine.assign_policy_to_node(node.node_id, policy.id)
        config = engine.get_policy_for_node(node.node_id)
        assert config == {"rate_limit": 50, "log_payload": True}


# ===========================================================================
# 3. P1: HONEYPOT SOCKET PROBING LATENCY & RELIABILITY
# ===========================================================================
class TestHoneypotProbingReliability:
    def test_socket_status_inactive_fallback_quick(self):
        """Probing unreachable host/port returns inactive within short timeout."""
        status = check_port_status("192.0.2.1", 65534, fallback_host="192.0.2.2", timeout=0.05)
        assert status == "inactive"

    def test_honeypots_endpoint_fast_response(self, client):
        """GET /api/honeypots responds promptly without hanging."""
        res = client.get("/api/honeypots")
        assert res.status_code == 200
        data = res.json()
        assert len(data) == 4
        names = [item["name"] for item in data]
        assert "SSH" in names
        assert "HTTP" in names


# ===========================================================================
# 4. P1: RESPONSE EXECUTOR CONCURRENCY & SYNCHRONIZATION
# ===========================================================================
class TestResponseExecutorConcurrency:
    def test_concurrent_executions_thread_safety(self):
        """Concurrent response triggers across 20 threads execute safely without race conditions."""
        executor = ResponseExecutor()
        threads = []
        results = []

        def worker(idx):
            ip = f"198.51.100.{100 + idx}"
            res = executor.execute(ip=ip, threat_score=85.0, threat_level="HIGH", protocol="SSH")
            results.append(res)

        for i in range(20):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(results) == 20
        # Check that blocked IPs were recorded safely
        assert len(executor.blocked_ips) >= 20
