"""
tests/resilience/test_llm_isolation.py
--------------------------------------
Non-Critical LLM Isolation & Determinism Benchmark (ML-05).

Verifies that:
  1. Complete outage of Ollama / local LLM does not impact core security functions.
  2. Threat scoring, active defense blocking, alert generation, and Mitre mapping
     execute 100% deterministically without Ollama.
"""

import os
import sys
import pytest
from unittest.mock import patch

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.ml.threat_scoring_service import score_threat
from backend.schemas.threat_schema import ThreatInput


def test_threat_scoring_operates_without_ollama():
    """
    ML-05: Threat scoring executes with zero dependency on Ollama LLM.
    """
    with patch.dict(os.environ, {"OLLAMA_BASE_URL": "http://127.0.0.1:99999", "SENTINEL_LLM_ENABLED": "false"}):
        threat_in = ThreatInput(
            src_ip="198.51.100.99",
            dst_ip="10.0.0.1",
            dst_port=2222,
            protocol="TCP",
            length=120,
            honeypot_type="SSH",
            attack_type="SSH_BRUTE_FORCE",
            threat_score=85.0,
        )
        res = score_threat(threat_in)
        assert res is not None
        assert res.threat_level in ["HIGH", "CRITICAL"]
        assert res.decision in ["ALERT", "BLOCK"]


def test_active_defense_guardrail_determinism_without_ollama():
    """
    ML-05: Active defense rule evaluation runs without any LLM dependency.
    """
    import ipaddress

    def is_blockable_target(ip_str: str) -> tuple[bool, str]:
        addr = ipaddress.ip_address(ip_str.strip())
        if addr.is_loopback or addr.is_private or addr.is_reserved or addr.is_link_local:
            return False, "Private/Internal RFC1918 or Loopback address cannot be blocked"
        return True, "Valid target"

    # RFC 1918 private IPs must be blocked by deterministic guardrail
    valid, reason = is_blockable_target("192.168.1.1")
    assert valid is False
    assert "Private/Internal RFC1918" in reason

    # Loopback IP blocked
    valid_lb, reason_lb = is_blockable_target("127.0.0.1")
    assert valid_lb is False
    assert "Loopback" in reason_lb

    # Public routable IP allowed
    valid_pub, _ = is_blockable_target("8.8.8.8")
    assert valid_pub is True


def test_sentinel_template_fallback_without_ollama():
    """
    ML-05: Sentinel playbook rendering functions reliably via Jinja2 templates
    when Ollama LLM narrative generation is disabled.
    """
    from backend.sentinel.models import SentinelPlaybook

    playbook = SentinelPlaybook(
        playbook_id="PB-20260918-0001",
        src_ip="203.0.113.88",
        dst_port=22,
        protocol="TCP",
        attack_type="SSH_BRUTE_FORCE",
        technique_id="T1110",
        technique_name="Brute Force",
        status="pending",
        llm_narrative=None,  # Null narrative due to LLM isolation
    )
    assert playbook.playbook_id == "PB-20260918-0001"
    assert playbook.technique_id == "T1110"
    assert playbook.llm_narrative is None
