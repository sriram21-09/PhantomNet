"""
tests/api/test_anomalies_api.py
-------------------------------
Verifies the /api/anomalies endpoint and the updated StatsService anomaly telemetry:
- Authentic data lineage from packet_logs.anomaly_score
- Dataset scoping (all, live, test)
- Severity calculations (high: score >= 0.70, medium: 0.40 <= score < 0.70)
- Average anomaly score calculation
- Recent anomaly event records
- RBAC authentication enforcement
"""
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from database.models import PacketLog
from services.stats_aggregator import StatsService


def seed_test_packet_logs(session):
    """Seed distinct live and test packet logs with realistic anomaly scores."""
    session.query(PacketLog).delete()
    session.commit()
    now = datetime.now(timezone.utc)
    packets = [
        # Live Honeypots (HTTP, SSH, SMTP)
        PacketLog(
            timestamp=now - timedelta(minutes=1),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=8080,
            protocol="HTTP",
            length=250,
            threat_score=85.0,
            threat_level="CRITICAL",
            anomaly_score=0.88,  # High anomaly (CRITICAL)
            attack_type="SQL_INJECTION",
        ),
        PacketLog(
            timestamp=now - timedelta(minutes=2),
            src_ip="192.168.1.101",
            dst_ip="10.0.0.1",
            dst_port=2722,
            protocol="SSH",
            length=180,
            threat_score=72.0,
            threat_level="HIGH",
            anomaly_score=0.74,  # High anomaly
            attack_type="SSH_BRUTE_FORCE",
        ),
        PacketLog(
            timestamp=now - timedelta(minutes=3),
            src_ip="192.168.1.102",
            dst_ip="10.0.0.1",
            dst_port=2725,
            protocol="SMTP",
            length=120,
            threat_score=45.0,
            threat_level="MEDIUM",
            anomaly_score=0.52,  # Medium anomaly
            attack_type="SPAM_PROBE",
        ),
        PacketLog(
            timestamp=now - timedelta(minutes=4),
            src_ip="192.168.1.103",
            dst_ip="10.0.0.1",
            dst_port=8080,
            protocol="HTTP",
            length=64,
            threat_score=10.0,
            threat_level="LOW",
            anomaly_score=0.0,  # Normal (not an anomaly)
            attack_type=None,
        ),
        # Test / Benchmark traffic (TCP)
        PacketLog(
            timestamp=now - timedelta(minutes=5),
            src_ip="198.51.100.10",
            dst_ip="10.0.0.2",
            dst_port=80,
            protocol="TCP",
            length=512,
            threat_score=60.0,
            threat_level="HIGH",
            anomaly_score=0.71,  # High anomaly in test
            attack_type="BENCHMARK_SYN",
        ),
        PacketLog(
            timestamp=now - timedelta(minutes=6),
            src_ip="198.51.100.11",
            dst_ip="10.0.0.2",
            dst_port=80,
            protocol="TCP",
            length=512,
            threat_score=42.0,
            threat_level="MEDIUM",
            anomaly_score=0.45,  # Medium anomaly in test
            attack_type="BENCHMARK_BURST",
        ),
        PacketLog(
            timestamp=now - timedelta(minutes=7),
            src_ip="198.51.100.12",
            dst_ip="10.0.0.2",
            dst_port=80,
            protocol="TCP",
            length=128,
            threat_score=5.0,
            threat_level="LOW",
            anomaly_score=0.0,  # Normal
            attack_type=None,
        ),
    ]
    session.add_all(packets)
    session.commit()


def test_anomalies_endpoint_requires_auth(client: TestClient):
    """Test that /api/anomalies rejects unauthenticated access with 401."""
    resp = client.get("/api/anomalies")
    assert resp.status_code == 401


def test_anomalies_all_mode(client: TestClient, viewer_headers: dict, db_session):
    """Test /api/anomalies in 'all' mode calculates metrics across all telemetry."""
    seed_test_packet_logs(db_session)

    resp = client.get("/api/anomalies?mode=all", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert data["mode"] == "all"
    assert data["totalEvents"] == 7
    # 5 packets have anomaly_score > 0
    assert data["totalAnomalies"] == 5
    # High: scores >= 0.70 -> 0.88, 0.74, 0.71 = 3
    assert data["highSeverity"] == 3
    # Medium: 0.40 <= score < 0.70 -> 0.52, 0.45 = 2
    assert data["mediumSeverity"] == 2
    # Verify recentAnomalies length and fields
    recent = data["recentAnomalies"]
    assert len(recent) == 5
    assert recent[0]["score"] == 88.0
    assert recent[0]["level"] == "CRITICAL"
    assert recent[0]["source_ip"] == "192.168.1.100"
    assert "score" in recent[0]
    assert "timestamp" in recent[0]


def test_anomalies_live_mode_filtering(client: TestClient, viewer_headers: dict, db_session):
    """Test /api/anomalies in 'live' mode strictly filters to honeypot sensors."""
    seed_test_packet_logs(db_session)

    resp = client.get("/api/anomalies?mode=live", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["mode"] == "live"
    # 4 honeypot packets (HTTP, SSH, SMTP)
    assert data["totalEvents"] == 4
    # 3 honeypot packets have anomaly_score > 0 (0.88, 0.74, 0.52)
    assert data["totalAnomalies"] == 3
    # High: 0.88, 0.74 = 2
    assert data["highSeverity"] == 2
    # Medium: 0.52 = 1
    assert data["mediumSeverity"] == 1
    # Recent anomalies should only be from live honeypots
    for item in data["recentAnomalies"]:
        assert item["protocol"] in ["HTTP", "SSH", "SMTP", "FTP"]


def test_anomalies_test_mode_filtering(client: TestClient, viewer_headers: dict, db_session):
    """Test /api/anomalies in 'test' mode strictly filters to benchmark telemetry."""
    seed_test_packet_logs(db_session)

    resp = client.get("/api/anomalies?mode=test", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["mode"] == "test"
    # 3 TCP benchmark packets
    assert data["totalEvents"] == 3
    # 2 have anomaly_score > 0 (0.71, 0.45)
    assert data["totalAnomalies"] == 2
    assert data["highSeverity"] == 1
    assert data["mediumSeverity"] == 1
    for item in data["recentAnomalies"]:
        assert item["protocol"] == "TCP"


def test_anomalies_empty_database(client: TestClient, viewer_headers: dict, db_session):
    """Test /api/anomalies returns legitimate zeros when no anomalies exist."""
    db_session.query(PacketLog).delete()
    db_session.commit()
    resp = client.get("/api/anomalies?mode=all", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["totalEvents"] == 0
    assert data["totalAnomalies"] == 0
    assert data["highSeverity"] == 0
    assert data["mediumSeverity"] == 0
    assert data["avgAnomalyScore"] == 0.0
    assert data["recentAnomalies"] == []


def test_stats_endpoint_includes_anomaly_telemetry(client: TestClient, viewer_headers: dict, db_session):
    """Test that /api/stats seamlessly includes anomaly metrics for cross-dashboard consistency."""
    seed_test_packet_logs(db_session)

    resp = client.get("/api/stats?mode=all", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()

    # Backwards compatibility check
    assert "totalEvents" in data
    assert "avgThreatScore" in data
    assert "avgAnomalyScore" in data
    assert "distribution" in data

    # New anomaly metrics present in unified stats
    assert data["totalAnomalies"] == 5
    assert data["highSeverity"] == 3
    assert data["mediumSeverity"] == 2
    assert isinstance(data["recentAnomalies"], list)
