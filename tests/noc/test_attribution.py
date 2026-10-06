"""
tests/noc/test_attribution.py
-----------------------------
Verifies authentication, canonical scoring, evidence provenance, and absence
of speculative labels for attack attribution endpoints:
- /api/v1/attribution/top-attackers
- /api/v1/attribution/profile/{ip}
"""
import pytest
from database.models import PacketLog


def test_attribution_authentication_rejected(client):
    """Verify unauthenticated access returns 401."""
    endpoints = [
        "/api/v1/attribution/top-attackers",
        "/api/v1/attribution/profile/192.168.1.100",
    ]
    for ep in endpoints:
        res = client.get(ep)
        assert res.status_code == 401, f"Endpoint {ep} must reject unauthenticated requests"


def test_attribution_top_attackers_success(client, auth_cookies, seed_packets):
    """Verify top-attackers returns canonical attributes and real evidence source."""
    res = client.get("/api/v1/attribution/top-attackers?limit=10", cookies=auth_cookies)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "evidence_source" in data
    assert "Database" in data["evidence_source"]
    assert len(data["attackers"]) > 0

    top = data["attackers"][0]
    assert "ip" in top
    assert "event_count" in top
    assert "avg_threat_score" in top
    assert "avg_threat_score_pct" in top
    assert "max_threat_score" in top
    assert "max_threat_score_pct" in top
    assert 0.0 <= top["avg_threat_score"] <= 1.0
    assert 0.0 <= top["avg_threat_score_pct"] <= 100.0


def test_attribution_profile_success(client, auth_cookies, seed_packets):
    """Verify profile for an identified attacker returns accurate evidence and progression."""
    res = client.get("/api/v1/attribution/profile/192.168.1.100", cookies=auth_cookies)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["ip"] == "192.168.1.100"
    assert "profile" in data
    assert "timeline" in data
    assert "progression" in data
    assert "confidence" in data
    assert 0 <= data["confidence"] <= 100

    profile = data["profile"]
    assert "sophistication" in profile
    assert "tools_detected" in profile
    assert "intent" in profile
    assert "protocols" in profile
    assert "attack_types" in profile

    # Verify no speculative labels
    soph_level = profile["sophistication"]["level"]
    assert "Script Kiddie" not in soph_level
    assert "State-Actor" not in soph_level


def test_attribution_profile_not_found(client, auth_cookies):
    """Verify profile for an unrecorded IP returns not_found status without crashing."""
    res = client.get("/api/v1/attribution/profile/10.0.99.99", cookies=auth_cookies)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "not_found"


def test_attribution_invalid_ip_format(client, auth_cookies):
    """Verify malformed IP returns 400 Bad Request."""
    res = client.get("/api/v1/attribution/profile/invalid-not-an-ip", cookies=auth_cookies)
    assert res.status_code == 400
