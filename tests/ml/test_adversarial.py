"""
tests/ml/test_adversarial.py
----------------------------
Adversarial Evasion Robustness Benchmark (ML-03).

Evaluates model resilience against:
  1. Low-and-slow brute force attacks (rate-limit evasion)
  2. Coordinated distributed attacks across multi-IP botnets
  3. Payload obfuscation and port rotation
"""

import os
import sys
import pytest

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.ml.threat_scoring_service import score_threat, map_score_to_level
from backend.schemas.threat_schema import ThreatInput


def test_slow_brute_force_detection():
    """
    ML-03: Slow brute force attempts spaced out to evade simple rate limiters
    must still be scored with elevated risk based on interaction context and sensitive port.
    """
    slow_threat = ThreatInput(
        src_ip="198.51.100.42",
        dst_ip="10.0.0.1",
        dst_port=22,
        protocol="TCP",
        length=88,
        honeypot_type="SSH",
        is_malicious=False,
        attack_type="SSH_BRUTE_FORCE",
    )

    res = score_threat(slow_threat)
    assert res is not None
    # Contextual adjustment: High interaction SSH honeypot implies elevated threat level
    assert res.threat_level in ["MEDIUM", "HIGH", "CRITICAL"]


def test_distributed_multi_ip_attack_correlation():
    """
    ML-03: Coordinated requests from multiple unique attacker IPs targeting
    the same honeypot infrastructure.
    """
    results = []
    for i in range(5):
        bot_input = ThreatInput(
            src_ip=f"203.0.113.{i+10}",
            dst_ip="10.0.0.5",
            dst_port=8080,
            protocol="TCP",
            length=350,
            honeypot_type="HTTP",
            attack_type="SQL_INJECTION",
            threat_score=65.0,
        )
        res = score_threat(bot_input)
        results.append(res)

    for res in results:
        assert res.decision in ["ALERT", "BLOCK"]
        assert res.threat_level in ["MEDIUM", "HIGH", "CRITICAL"]


def test_payload_mutation_and_evasion():
    """
    ML-03: Obfuscated or mutated payload attempts on unusual ports
    must maintain deterministic heuristic fallback scoring.
    """
    mutated_input = ThreatInput(
        src_ip="192.0.2.1",
        dst_ip="10.0.0.1",
        dst_port=2222,  # Non-standard SSH honeypot port
        protocol="TCP",
        length=2048,
        attack_type="EXPLOIT_PAYLOAD",
    )
    res = score_threat(mutated_input)
    # Without artificial is_malicious bypass, verify real model scoring
    assert res.threat_level in ["MEDIUM", "HIGH", "CRITICAL"]
    assert res.decision in ["ALERT", "BLOCK"]
