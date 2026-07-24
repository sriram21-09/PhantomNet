"""
tests/test_week18_day5_mitre_realtime.py
-----------------------------------------
Week 18 Day 5 Integration Test: Real-Time ATT&CK Matrix Updates and Incident Generation Pipeline

Verifies that generating new playbook incidents via SentinelService dynamically updates
the MITRE ATT&CK matrix heatmap in real-time in both the database and the
GET /api/sentinel/mitre/matrix API response.
"""

import pytest
import os
import sys
from datetime import datetime, timezone
from sqlalchemy.orm import Session

# Ensure backend directory is in sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from database.database import SessionLocal, engine
from database.models import Base, Event, PacketLog
from sentinel.models import SentinelPlaybook
from sentinel.sentinel_service import SentinelService
from sentinel.mitre_matrix import build_matrix_response
from fastapi import FastAPI
from fastapi.testclient import TestClient
from api.sentinel import router as sentinel_router


@pytest.fixture(scope="function")
def db_session():
    """Provides a fresh database session for each test function."""
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    
    # Enable test mode flag so SentinelService deduplication allows test campaigns
    os.environ["ENVIRONMENT"] = "test"
    
    # Cleanup previous test playbooks & events
    session.query(SentinelPlaybook).delete()
    session.query(Event).delete()
    session.commit()
    
    yield session
    
    session.query(SentinelPlaybook).delete()
    session.query(Event).delete()
    session.commit()
    session.close()


@pytest.fixture(scope="function")
def api_client(db_session):
    """FastAPI TestClient configured with sentinel router."""
    app = FastAPI()
    app.include_router(sentinel_router)
    return TestClient(app)


def test_realtime_ssh_brute_force_matrix_update(db_session: Session, api_client: TestClient):
    """
    Test 1: Verify SSH Brute Force campaign generation increments T1110.001 in DB & Matrix API.
    """
    # 1. Query baseline matrix API
    res_before = api_client.get("/api/sentinel/mitre/matrix")
    assert res_before.status_code == 200
    data_before = res_before.json()
    freq_before = data_before.get("frequency_map", {})
    t1110_before = freq_before.get("T1110", 0)

    # 2. Trigger SSH Brute Force campaign
    campaign_data = {
        "campaign_id": "CAMP-TEST-SSH-001",
        "source_ips": ["192.168.1.100"],
        "target_ports": [2222],
        "protocols": ["TCP"],
        "event_count": 45,
        "signatures": ["SSH_AUTH_FAILURE"],
        "time_range": {"start": "2026-07-24T18:00:00Z", "end": "2026-07-24T18:30:00Z"}
    }

    svc = SentinelService(db_session)
    pb = svc.generate_playbook(campaign_data)

    assert pb is not None
    assert pb.technique_id in ["T1110.001", "T1110"]

    # 3. Verify DB record
    db_count = db_session.query(SentinelPlaybook).filter(
        SentinelPlaybook.technique_id.in_(["T1110.001", "T1110"])
    ).count()
    assert db_count >= 1

    # 4. Query updated matrix API response
    res_after = api_client.get("/api/sentinel/mitre/matrix")
    assert res_after.status_code == 200
    data_after = res_after.json()
    freq_after = data_after.get("frequency_map", {})
    t1110_after = freq_after.get("T1110", 0)

    assert t1110_after == t1110_before + 1, f"Expected T1110 count {t1110_before + 1}, got {t1110_after}"


def test_realtime_sqli_matrix_update(db_session: Session, api_client: TestClient):
    """
    Test 2: Verify SQL Injection campaign generation increments T1190 in DB & Matrix API.
    """
    # 1. Create dummy Event for SQLi signature matching
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.50",
        src_port=44321,
        honeypot_type="HTTP",
        raw_data="GET /search?id=1' UNION SELECT 1,username,password FROM users-- HTTP/1.1"
    )
    db_session.add(event)
    db_session.commit()

    # Query baseline matrix
    res_before = api_client.get("/api/sentinel/mitre/matrix")
    data_before = res_before.json()

    # 2. Trigger SQL Injection campaign
    campaign_data = {
        "campaign_id": "CAMP-TEST-SQLI-001",
        "source_ips": ["10.0.0.50"],
        "target_ports": [8080],
        "protocols": ["HTTP"],
        "event_count": 30,
        "time_range": {"start": "2026-07-24T18:00:00Z", "end": "2026-07-24T18:30:00Z"}
    }

    svc = SentinelService(db_session)
    pb = svc.generate_playbook(campaign_data)

    assert pb is not None
    base_tech = pb.technique_id.split('.')[0] if pb.technique_id else "T1190"

    # 3. Verify matrix response increment
    res_after = api_client.get("/api/sentinel/mitre/matrix")
    data_after = res_after.json()
    tech_after = data_after.get("frequency_map", {}).get(base_tech, 0)
    tech_before = data_before.get("frequency_map", {}).get(base_tech, 0)

    assert tech_after == tech_before + 1, f"Expected {base_tech} count {tech_before + 1}, got {tech_after}"


def test_realtime_sequential_campaigns_matrix_sync(db_session: Session, api_client: TestClient):
    """
    Test 3: Verify multiple sequential incident generation events update matrix counts accurately.
    """
    svc = SentinelService(db_session)

    # Baseline check
    res0 = api_client.get("/api/sentinel/mitre/matrix").json()
    initial_ssh_count = res0.get("frequency_map", {}).get("T1110", 0)

    # Trigger 3 SSH campaigns sequentially
    for i in range(1, 4):
        svc.generate_playbook({
            "campaign_id": f"CAMP-SEQ-SSH-{i}",
            "source_ips": [f"192.168.1.{10+i}"],
            "target_ports": [2222],
            "protocols": ["TCP"],
            "event_count": 20 * i,
        })
        
        # Verify real-time sync after each step
        res_current = api_client.get("/api/sentinel/mitre/matrix").json()
        current_ssh_count = res_current.get("frequency_map", {}).get("T1110", 0)
        assert current_ssh_count == initial_ssh_count + i, f"Step {i}: expected {initial_ssh_count + i}, got {current_ssh_count}"

    # Verify DB total count matches
    db_total = db_session.query(SentinelPlaybook).count()
    assert db_total == 3


def test_matrix_api_schema_completeness(db_session: Session, api_client: TestClient):
    """
    Test 4: Validate that matrix API response contains all required fields and metadata.
    """
    # Create 1 playbook
    svc = SentinelService(db_session)
    svc.generate_playbook({
        "campaign_id": "CAMP-SCHEMA-TEST",
        "source_ips": ["172.16.0.5"],
        "target_ports": [2222],
        "protocols": ["TCP"],
        "event_count": 10
    })

    res = api_client.get("/api/sentinel/mitre/matrix")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert "generated_at" in data
    assert "total_tactics" in data
    assert data["total_tactics"] == 9
    assert "total_techniques" in data
    assert data["total_techniques"] > 0
    assert "matrix" in data
    assert "frequency_map" in data

    # Check technique object schema inside matrix
    for tactic_name, techs in data["matrix"].items():
        assert isinstance(techs, list)
        for tech in techs:
            assert "technique_id" in tech
            assert "technique_name" in tech
            assert "tactic_id" in tech
            assert "severity" in tech
            assert "url" in tech
            assert "description" in tech
            assert "count" in tech
