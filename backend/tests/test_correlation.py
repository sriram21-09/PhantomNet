import pytest
from backend.ml.threat_correlation import ThreatCorrelator

@pytest.fixture
def correlator():
    return ThreatCorrelator()

def test_sql_injection_detection(correlator):
    """Test that rule-based engine catches SQLi."""
    log = {
        "service_type": "HTTP",
        "payload": "UNION SELECT * FROM users",
        "attacker_ip": "1.2.3.4"
    }
    result = correlator.analyze_log(log)
    
    assert "HTTP_SQL_INJECTION" in result["details"]["signatures_triggered"]
    assert result["total_risk_score"] > 20 # Should have some risk

def test_threat_feed_hit(correlator):
    """Test that known bad IPs trigger critical alerts."""
    log = {
        "service_type": "SSH",
        "attacker_ip": "192.168.1.100", # Known Botnet in our mock feed
        "payload": "ping"
    }
    result = correlator.analyze_log(log)
    
    assert result["details"]["threat_intel_match"] == "KNOWN_BOTNET"
    assert result["verdict"] in ["HIGH", "CRITICAL"]

def test_safe_traffic(correlator):
    """Test that normal traffic gets a low score."""
    log = {
        "service_type": "HTTP",
        "payload": "GET /index.html",
        "attacker_ip": "8.8.8.8"
    }
    result = correlator.analyze_log(log)
    
    assert result["verdict"] == "SAFE"
    assert result["total_risk_score"] < 20
