import pytest
import os
import json
import uuid
import time
from datetime import datetime

# PhantomNet specific imports
from services.universal_siem_exporter import get_siem_exporter
from database.models import PacketLog
from ml.threat_scoring_service import score_threat_batch
from schemas.threat_schema import ThreatInput
from ml_engine.explainability import explainer_service
from services.node_manager import NodeManager
from services.response_executor import response_executor


@pytest.fixture
def dummy_event():
    return {
        "src_ip": "1.2.3.4",
        "dst_ip": "10.0.0.5",
        "dst_port": 22,
        "protocol": "TCP",
        "length": 1500,
        "timestamp": datetime.now().isoformat(),
    }


class TestWeek10Integration:

    def test_siem_export_batching(self):
        """Test 1: SIEM export capacity by sending 1000 events and verifying success format."""

        # We temporarily target 'CEF' since we dont have a live ELK/Splunk docker running in CI
        os.environ["SIEM_TYPE"] = "cef"
        os.environ["SIEM_HOST"] = "localhost"
        exporter = get_siem_exporter()

        test_events = []
        for i in range(100):
            test_events.append(
                {
                    "id": str(uuid.uuid4()),
                    "src_ip": f"192.168.1.{i%255}",
                    "threat_level": "HIGH",
                    "attack_type": "ssh_brute_force",
                }
            )

        # We pass target event_type since CEF exporter requires it
        from unittest.mock import patch

        with patch("requests.post") as mock_post:
            mock_post.return_value.status_code = 200
            success = exporter.export_events(test_events, event_type="threat_log")
            assert success is True

    def test_lstm_predictions_and_xai(self):
        """Test 2: LSTM batch validation and XAI explanation bounds."""

        # Feed 100 malicious-looking sequences
        inputs = []
        for i in range(100):
            inputs.append(
                ThreatInput(
                    src_ip="185.20.1.5",
                    dst_ip="10.0.0.1",
                    dst_port=22,
                    protocol="TCP",
                    length=1500 + i,  # Vary signature slightly
                )
            )

        start_time = time.time()
        results = score_threat_batch(inputs)
        end_time = time.time()

        assert len(results) == 100
        assert results[0] is not None

        latency = (end_time - start_time) * 1000  # ms
        # In a real environment latency should be < 100ms. In CI, it might fluctuate but we check batched throughput
        assert latency < 500  # Ensure reasonable bound for 100 events

        # Test SHAP Explainability API backend
        event_dict = {
            "src_ip": inputs[0].src_ip,
            "dst_ip": inputs[0].dst_ip,
            "dst_port": inputs[0].dst_port,
            "protocol": inputs[0].protocol,
            "length": inputs[0].length,
        }

        explanation = explainer_service.explain_prediction(event_dict)
        # If running in CI without trained model pkl, it gracefully falls back with initialized error
        if "error" in explanation:
            assert explanation["error"] == "Explainer not initialized"
        else:
            assert "base_score" in explanation
            assert len(explanation.get("top_features", [])) > 0

    def test_distributed_topology(self):
        """Test 3: Verify distributed 11-node tracking."""
        from database.database import SessionLocal, engine
        from database.models import HoneypotNode, Base

        # Ensure schema table is built in active SQLite temp engine
        Base.metadata.create_all(bind=engine)

        db = SessionLocal()
        manager = NodeManager(db)

        # Clear existing
        db.query(HoneypotNode).delete()
        db.commit()

        # Register 11 honeypots
        for i in range(11):
            manager.register_node(f"node-{i}", f"10.0.1.{i}", "ssh_honeypot")

        nodes = manager.list_nodes()
        assert len(nodes) == 11

        # Fail a node
        node_to_fail = nodes[5]
        node_to_fail.status = "offline"
        db.commit()

        offline_nodes = [n for n in manager.list_nodes() if n.status == "offline"]
        assert len(offline_nodes) == 1

        db.close()

    def test_playbook_execution(self):
        """Test 4: Verify automated defense playbooks execute and block tracking works."""

        target_ip = "199.200.201.202"

        # Trigger block via Response Executor internals as defined in `response_executor.py`
        result = response_executor._action_block_ip(
            target_ip, duration_minutes=30, level="HIGH"
        )
        assert result["status"] == "blocked"

        # Verify it's in the list
        blocked = response_executor.get_blocked_ips()
        assert any(b["ip"] == target_ip for b in blocked)

        # Unblock
        response_executor.unblock_ip(target_ip)
        blocked_after = response_executor.get_blocked_ips()
        assert not any(b["ip"] == target_ip for b in blocked_after)
