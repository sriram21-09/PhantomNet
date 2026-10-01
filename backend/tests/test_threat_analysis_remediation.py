"""
Automated Regression and Data Lineage Tests for Threat Analysis Remediation.
Verifies TA-01 through TA-07 fixes:
- Authoritative summary counts (not 20-event length)
- Historical high/critical attacks included in High Severity card
- Threat type separated from enforcement decision (never 'ALLOW' as attack type)
- Genuine alert filtering (no benign ALLOW traffic in alerts)
- Accurate presentation score conversion (no fake mappings)
- Authentication enforcement (401 on unauthorized access)
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone

from backend.main import app
from backend.database.models import Base, PacketLog, User
from backend.database.database import get_db
from backend.services.stats_aggregator import StatsService

# Create in-memory SQLite database for deterministic unit testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def seed_test_database():
    """Seed test dataset containing > 20 events with various threat levels."""
    db = TestingSessionLocal()
    db.query(PacketLog).delete()

    # Seed 5 CRITICAL events
    for i in range(5):
        db.add(PacketLog(
            timestamp=datetime.now(timezone.utc),
            src_ip=f"198.51.100.{10+i}",
            protocol="HTTP",
            dst_port=8080,
            attack_type="SQL_INJECTION",
            threat_score=0.92,
            threat_level="CRITICAL",
            is_malicious=True,
        ))

    # Seed 10 HIGH events
    for i in range(10):
        db.add(PacketLog(
            timestamp=datetime.now(timezone.utc),
            src_ip=f"172.19.0.{20+i}",
            protocol="SSH",
            dst_port=2222,
            attack_type="BRUTE_FORCE",
            threat_score=0.74,
            threat_level="HIGH",
            is_malicious=True,
        ))

    # Seed 6 MEDIUM events
    for i in range(6):
        db.add(PacketLog(
            timestamp=datetime.now(timezone.utc),
            src_ip=f"172.19.0.{40+i}",
            protocol="FTP",
            dst_port=2121,
            attack_type="PORT_SCAN",
            threat_score=0.48,
            threat_level="MEDIUM",
            is_malicious=False,
        ))

    # Seed 30 LOW / BENIGN events with decision='ALLOW'
    for i in range(30):
        db.add(PacketLog(
            timestamp=datetime.now(timezone.utc),
            src_ip=f"172.18.0.{100+i}",
            protocol="HTTP",
            dst_port=80,
            attack_type="ALLOW",
            threat_score=0.15,
            threat_level="LOW",
            is_malicious=False,
        ))

    db.commit()
    yield
    db.close()


def test_ta01_active_threat_count_authoritative():
    """TEST 1: Active threats count must not equal 20 (arbitrary pagination limit)."""
    db = TestingSessionLocal()
    service = StatsService(db)
    summary = service.get_threat_summary(mode="all")

    # 5 Critical + 10 High + 6 Medium = 21 Active Threats
    assert summary["activeThreats"] == 21
    assert summary["totalEvents"] == 51  # 5 + 10 + 6 + 30
    assert summary["activeThreats"] != 20
    db.close()


def test_ta02_historical_high_severity_retention():
    """TEST 2: Historical high severity attacks are retained regardless of recent benign traffic."""
    db = TestingSessionLocal()
    service = StatsService(db)
    summary = service.get_threat_summary(mode="all")

    # 5 Critical + 10 High = 15 High Severity
    assert summary["highSeverity"] == 15
    assert summary["mediumSeverity"] == 6
    assert summary["lowSeverity"] == 30
    db.close()


def test_ta03_benign_allow_not_treated_as_attack_type():
    """TEST 3: Threat type must not be 'ALLOW' for benign traffic."""
    db = TestingSessionLocal()
    service = StatsService(db)
    indicators = service.get_recent_threat_indicators(limit=10, mode="all")

    for ind in indicators:
        # Attack type must NEVER be 'ALLOW'
        assert ind["attack_type"] != "ALLOW"
        assert ind["type"] != "ALLOW"
        if ind["threat_level"] == "LOW":
            assert ind["attack_type"] == "BENIGN"
            assert ind["decision"] == "ALLOW"
    db.close()


def test_ta04_live_alerts_feed_excludes_benign():
    """TEST 4: Live alerts feed contains only genuine threats (HIGH, CRITICAL)."""
    db = TestingSessionLocal()
    service = StatsService(db)
    alerts = service.get_live_threat_alerts(limit=20, mode="all")

    assert len(alerts) == 15  # 5 Critical + 10 High
    for alert in alerts:
        assert alert["threat_level"] in ("CRITICAL", "HIGH")
        assert "ALLOW" not in alert["message"]
        assert alert["severity"] == "high"
    db.close()


def test_ta05_score_percentage_conversion():
    """TEST 5: Scores are converted mathematically without fake categorical mappings."""
    db = TestingSessionLocal()
    service = StatsService(db)
    indicators = service.get_recent_threat_indicators(limit=50, mode="all")

    for ind in indicators:
        # Raw threat_score 0.92 -> score 92.0
        # Raw threat_score 0.74 -> score 74.0
        # Raw threat_score 0.48 -> score 48.0
        # Raw threat_score 0.15 -> score 15.0
        expected_score = round(ind["threat_score"] * 100, 1)
        assert ind["score"] == expected_score
    db.close()


def test_ta06_unauthenticated_api_rejection():
    """TEST 6: API endpoints enforce authentication (401 when unauthorized)."""
    unauth_client = TestClient(app)
    r1 = unauth_client.get("/api/threats/summary")
    assert r1.status_code == 401

    r2 = unauth_client.get("/api/threats/alerts")
    assert r2.status_code == 401

    r3 = unauth_client.get("/api/threats/indicators")
    assert r3.status_code == 401

    r4 = unauth_client.get("/api/events")
    assert r4.status_code == 401
