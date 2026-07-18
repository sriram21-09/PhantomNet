import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from sqlalchemy.orm import Session

from sentinel.sentinel_service import SentinelService, _run_llm_narrative_bg
from sentinel.models import SentinelPlaybook
from fastapi import BackgroundTasks


class MockPlaybook:
    """Minimal SentinelPlaybook stand-in for unit tests."""

    def __init__(self):
        self.id = 42
        self.playbook_id = "PB-20260716-123456-ABCDEF"
        self.playbook_name = "SSH Brute Force Mitigations"
        self.attack_type = "Brute Force"
        self.technique_id = "T1021.004"
        self.technique_name = "SSH"
        self.tactic = "Lateral Movement"
        self.severity = "high"
        self.threat_score = 85
        self.src_ip = "192.168.1.100"
        self.dst_port = 22
        self.protocol = "TCP"
        self.llm_narrative = None
        self.updated_at = None


def test_sentinel_service_schedules_fastapi_background_tasks():
    """Verify generate_playbook registers background task when BackgroundTasks is provided."""
    mock_db = MagicMock(spec=Session)
    mock_bg = MagicMock(spec=BackgroundTasks)

    # Mock all the sub-component calls inside generate_playbook to isolate the LLM call
    mock_playbook = SentinelPlaybook(
        id=42,
        playbook_id="PB-TEST-123",
        attack_type="Brute Force",
        severity="HIGH",
        src_ip="192.168.1.100",
        dst_port=22,
        protocol="TCP",
    )

    campaign_data = {
        "source_ips": ["192.168.1.100"],
        "target_ports": [22],
        "protocols": ["TCP"],
        "event_count": 5,
        "campaign_id": "CAMP-123",
    }

    svc = SentinelService(mock_db)
    
    # Mock template render return
    mock_gen = MagicMock()
    mock_gen.render.return_value = ("Test PB", "Test PB Content", "ssh.j2")
    svc._playbook_gen = mock_gen

    # Mock the internal methods so generate_playbook runs without real DB dependencies
    with patch.object(svc, "_infer_service", return_value="SSH"), \
         patch.object(svc, "_query_packet_logs", return_value=[]), \
         patch.object(svc, "_query_iocs", return_value=[]), \
         patch.object(svc, "_run_signature_analysis", return_value=["SSH_AUTH_FAILURE"]), \
         patch.object(svc, "_store_signatures", return_value=0), \
         patch("sentinel.sentinel_service.generate_rules_for_campaign", return_value={"snort_rules": "rule", "sigma_rules": "sigma", "metadata": {"snort_rule_count": 1, "sigma_rule_count": 1}}), \
         patch("sentinel.sentinel_service.build_stix_bundle", return_value=MagicMock(objects=[])), \
         patch("sentinel.sentinel_service.bundle_to_json", return_value="{}"), \
         patch("sentinel.sentinel_service.calculate_confidence", return_value=MagicMock(confidence=0.9, severity="HIGH", cluster_size_score=0.9, ml_avg_score=0.9, ioc_density=0.9, multi_proto_bonus=0.0, breakdown={})), \
         patch("sentinel.sentinel_service.logger") as mock_logger:

        # Mock db save
        def mock_add(obj):
            obj.id = 42

        mock_db.add.side_effect = mock_add

        # Execute generate_playbook
        res = svc.generate_playbook(campaign_data, background_tasks=mock_bg)

        # Check if background task is added
        mock_bg.add_task.assert_called_once_with(_run_llm_narrative_bg, 42)


@patch("database.database.SessionLocal")
@patch("sentinel.llm_service.LLMService")
def test_run_llm_narrative_bg_success(mock_llm_service_cls, mock_session_local):
    """Verify _run_llm_narrative_bg fetches playbook, calls LLMService, and commits."""
    mock_db = MagicMock(spec=Session)
    mock_session_local.return_value = mock_db

    mock_playbook = MockPlaybook()
    mock_db.query.return_value.filter.return_value.first.return_value = mock_playbook

    mock_llm_svc = MagicMock()
    mock_llm_svc.generate_narrative.return_value = "Mocked Narrative Summary Text\n"
    mock_llm_service_cls.return_value = mock_llm_svc

    # Run background task
    _run_llm_narrative_bg(42)

    # Verify LLMService was called with correct context keys
    mock_llm_svc.generate_narrative.assert_called_once()
    context = mock_llm_svc.generate_narrative.call_args[0][0]
    assert context["attack_type"] == "Brute Force"
    assert context["src_ip"] == "192.168.1.100"
    assert context["dst_port"] == 22
    assert context["protocol"] == "TCP"

    # Verify db update and commit
    assert mock_playbook.llm_narrative == "Mocked Narrative Summary Text\n"
    mock_db.commit.assert_called_once()
    mock_db.close.assert_called_once()


@patch("database.database.SessionLocal")
@patch("sentinel.llm_service.LLMService")
def test_run_llm_narrative_bg_failure_handles_gracefully(mock_llm_service_cls, mock_session_local):
    """Verify _run_llm_narrative_bg logs error and does not commit on LLMService failure."""
    mock_db = MagicMock(spec=Session)
    mock_session_local.return_value = mock_db

    mock_playbook = MockPlaybook()
    mock_db.query.return_value.filter.return_value.first.return_value = mock_playbook

    mock_llm_svc = MagicMock()
    mock_llm_svc.generate_narrative.side_effect = Exception("Ollama offline")
    mock_llm_service_cls.return_value = mock_llm_svc

    # Run background task
    _run_llm_narrative_bg(42)

    # Verify db commit is NOT called on failure
    assert mock_playbook.llm_narrative is None
    mock_db.commit.assert_not_called()
    mock_db.close.assert_called_once()
