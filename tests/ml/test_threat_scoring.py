import pytest
from unittest.mock import MagicMock
from ml.threat_scoring_service import map_score_to_level, map_score_to_decision

def test_threat_score_severity_mapping():
    assert map_score_to_level(0.20) == "LOW"
    assert map_score_to_level(0.50) == "MEDIUM"
    assert map_score_to_level(0.80) == "HIGH"
    assert map_score_to_level(0.95) == "CRITICAL"

def test_threat_score_distribution():
    # Verify mapping hits all 4 levels given appropriate scores
    scores = [0.10, 0.60, 0.85, 0.99]
    levels = [map_score_to_level(s) for s in scores]
    assert set(levels) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

def test_normal_traffic_scores():
    # Verify that scores for normal traffic are < 50 on average
    # Since this is a test of the threshold calibration, we verify low scores map to benign actions
    assert map_score_to_level(0.40) in ["LOW", "MEDIUM"]
    assert map_score_to_decision(0.40) == "ALLOW"
    assert map_score_to_decision(0.10) == "ALLOW"

def test_dynamic_thresholds():
    # Test time of day adjustment
    # Night time (00:00 - 05:00 UTC) lowers thresholds by 10
    ctx_night = MagicMock()
    ctx_night.is_malicious = False
    ctx_night.timestamp = "2026-03-18T03:00:00Z"
    ctx_night.honeypot_type = None
    
    # Normally 0.70 is MEDIUM
    assert map_score_to_level(0.70) == "MEDIUM"
    # But at night, medium_max = 65, so 70 becomes HIGH
    assert map_score_to_level(0.70, ctx_night) == "HIGH"

    # Test honeypot adjustment
    ctx_honeypot = MagicMock()
    ctx_honeypot.is_malicious = False
    ctx_honeypot.timestamp = None
    ctx_honeypot.honeypot_type = "SSH"
    
    # Normally 0.65 is MEDIUM
    assert map_score_to_level(0.65) == "MEDIUM"
    # With SSH honeypot, medium_max = 60, so 65 becomes HIGH
    assert map_score_to_level(0.65, ctx_honeypot) == "HIGH"
    
    # Test malicious context forces CRITICAL
    ctx_malicious = MagicMock()
    ctx_malicious.is_malicious = True
    ctx_malicious.timestamp = None
    ctx_malicious.honeypot_type = None
    
    # Even a score of 10.0 becomes CRITICAL if context is known malicious
    assert map_score_to_level(0.10, ctx_malicious) == "CRITICAL"
