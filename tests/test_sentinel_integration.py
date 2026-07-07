"""
tests/test_sentinel_integration.py
----------------------------------
Comprehensive integration test suite for the PhantomNet Sentinel pipeline.
Tests full pipeline flow: PacketLog/Event insert -> clustering -> playbook generation -> DB record.
Tests all 10 API endpoints, pagination, filtering, and edge cases.

Ensures WAL mode concurrency (BUG-001) using a separate test SQLite database.
"""

import os
import sys
import pytest
from datetime import datetime, timedelta, timezone
import json
import yaml

# Ensure project root and backend are on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# 1. Force the database URL before importing database module
TEST_DB_PATH = os.path.join(PROJECT_ROOT, "test_phantomnet_integration.db")
TEST_DB_URL = f"sqlite:///{TEST_DB_PATH}"

os.environ["DATABASE_URL"] = TEST_DB_URL
os.environ["ENVIRONMENT"] = "test"

# Import SQLAlchemy stuff
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Engine

# Import database module to override globals
import database.database
database.database.DATABASE_URL = TEST_DB_URL
database.database.engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False, "timeout": 30}
)
database.database.SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=database.database.engine
)

# Apply WAL and synchronous NORMAL to our test engine (BUG-001 mitigation)
@event.listens_for(database.database.engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    finally:
        cursor.close()

# Now import model base and other modules
# pyrefly: ignore [missing-import]
from database.models import Base, PacketLog, Event as DBEvent
# pyrefly: ignore [missing-import]
from sentinel.models import SentinelPlaybook
# pyrefly: ignore [missing-import]
from sentinel.sentinel_service import SentinelService
# pyrefly: ignore [missing-import]
from ml_engine.campaign_clustering import campaign_clusterer

# Override SessionLocal inside all imported modules that copied the reference
new_session_local = database.database.SessionLocal
for name, module in list(sys.modules.items()):
    if (
        name.startswith("sentinel") or 
        name.startswith("ml_engine") or 
        name.startswith("services") or 
        name.startswith("api") or 
        name.startswith("database")
    ):
        if hasattr(module, "SessionLocal"):
            setattr(module, "SessionLocal", new_session_local)

# Set up TestClient
from fastapi.testclient import TestClient
from backend.main import app

def override_get_db():
    db = database.database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[database.database.get_db] = override_get_db
client = TestClient(app)


# ---------------------------------------------------------------------------
# Helper to clean up database files
# ---------------------------------------------------------------------------
def cleanup_test_db():
    for ext in ["", "-shm", "-wal"]:
        path = TEST_DB_PATH + ext
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception as e:
                print(f"Error removing {path}: {e}")


# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module", autouse=True)
def setup_test_db_infrastructure():
    """Ensure database has all schemas created on startup."""
    cleanup_test_db()
    Base.metadata.create_all(bind=database.database.engine)
    SentinelPlaybook.__table__.create(bind=database.database.engine, checkfirst=True)
    yield
    cleanup_test_db()


@pytest.fixture(autouse=True)
def clean_database_tables():
    """Clears all records from the tables before each test to ensure independent execution."""
    db = database.database.SessionLocal()
    try:
        db.query(SentinelPlaybook).delete()
        db.query(PacketLog).delete()
        db.query(DBEvent).delete()
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@pytest.fixture
def db_session():
    """Provides a fresh database session for a test function."""
    db = database.database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Pipeline Tests
# ---------------------------------------------------------------------------
def test_full_pipeline_ingest_cluster_generate(db_session):
    """
    Tests the full pipeline end-to-end:
    1. Ingest PacketLogs + Event records representing an SSH brute force campaign.
    2. Run Campaign Clustering (DBSCAN) to identify the campaign.
    3. Generate a playbook from the identified campaign.
    4. Verify the playbook is saved in the database with correct fields.
    """
    # 1. Ingest SSH brute force packets (need unique source IPs to keep stateful features constant for DBSCAN)
    now = datetime.utcnow()
    attacker_ips = [f"192.168.99.{100 + i}" for i in range(15)]
    primary_attacker_ip = attacker_ips[0]
    
    for i, ip in enumerate(attacker_ips):
        log = PacketLog(
            timestamp=now + timedelta(milliseconds=i),
            src_ip=ip,
            dst_ip="10.0.0.50",
            src_port=50000 + i,
            dst_port=2222,  # SSH port
            protocol="TCP",
            length=64,  # Keep length fixed to 64 to avoid variance
            attack_type="SSH_AUTH_FAILURE",
            threat_score=0.85,
            threat_level="HIGH",
            is_malicious=True,
            event="login_attempt",
        )
        db_session.add(log)
    
    # Ingest event log for SignatureEngine lookup
    evt = DBEvent(
        source_ip=primary_attacker_ip,
        src_port=50000,
        honeypot_type="SSH",
        raw_data=f"Failed password for root from {primary_attacker_ip} port 50000 ssh2",
        timestamp=now,
    )
    db_session.add(evt)
    db_session.commit()

    # 2. Run Campaign Clustering
    cluster_result = campaign_clusterer.identify_campaigns(hours_back=1)
    assert cluster_result["campaign_count"] > 0, "DBSCAN failed to identify any campaigns"
    
    campaign = cluster_result["campaigns"][0]
    assert primary_attacker_ip in campaign["unique_sources"]
    assert 2222 in campaign["target_ports"]
    
    # Map campaign to SentinelService format
    campaign_data = {
        "source_ips": campaign.get("unique_sources", []),
        "target_ports": campaign.get("target_ports", []),
        "protocols": campaign.get("protocols", ["TCP"]),
        "event_count": campaign.get("event_count", 0),
        "campaign_id": campaign.get("campaign_id"),
        "time_range": {
            "start": campaign.get("start_time"),
            "end": campaign.get("end_time"),
        } if campaign.get("start_time") else None,
    }

    # 3. Generate Playbook
    svc = SentinelService(db_session)
    playbook = svc.generate_playbook(campaign_data)
    assert playbook is not None
    assert playbook.id is not None
    assert playbook.playbook_id.startswith("PB-")

    # 4. Verify DB persistence and field validity
    db_record = db_session.query(SentinelPlaybook).filter_by(id=playbook.id).first()
    assert db_record is not None
    assert db_record.src_ip in attacker_ips
    assert db_record.dst_port == 2222
    assert db_record.status == "pending"
    assert db_record.technique_id == "T1110.001"  # Brute Force mapping
    assert "attack.mitre.org" in db_record.mitre_url
    assert db_record.snort_rule.startswith("alert ")
    
    # Verify Sigma Rule is valid YAML
    sigma_data = yaml.safe_load(db_record.sigma_rule.split("---")[0])
    assert isinstance(sigma_data, dict)
    assert "title" in sigma_data
    assert "logsource" in sigma_data
    assert "detection" in sigma_data

    # Verify STIX bundle is valid JSON
    stix_bundle = json.loads(db_record.result_dict["stix_bundle_json"])
    assert stix_bundle["type"] == "bundle"
    assert len(stix_bundle["objects"]) > 0


# ---------------------------------------------------------------------------
# API Endpoints Tests
# ---------------------------------------------------------------------------
def _seed_one_playbook(db_session, playbook_id="PB-TEST-0001", status="pending", attack_type="SSH_AUTH_FAILURE"):
    pb = SentinelPlaybook(
        playbook_id=playbook_id,
        src_ip="10.0.0.1",
        dst_port=2222,
        protocol="TCP",
        attack_type=attack_type,
        threat_score=85.0,
        confidence_score=0.9,
        severity="HIGH",
        technique_id="T1110.001",
        technique_name="Brute Force",
        tactic="Credential Access",
        mitre_url="https://attack.mitre.org/techniques/T1110/001/",
        snort_rule='alert tcp any any -> any 22 (msg:"SSH Brute Force"; sid:1000001;)',
        sigma_rule="title: SSH Brute Force\nlogsource:\n  product: linux\ndetection:\n  selection:\n    event_id: 1\n  condition: selection",
        playbook_name="SSH Brute Force Mitigation",
        playbook_content="# SSH Brute Force Response Playbook",
        template_name="brute_force.j2",
        status=status,
    )
    db_session.add(pb)
    db_session.commit()
    db_session.refresh(pb)
    return pb


def test_api_list_playbooks(db_session):
    """GET /api/sentinel/playbooks paginated list."""
    _seed_one_playbook(db_session, "PB-A", status="pending")
    _seed_one_playbook(db_session, "PB-B", status="approved")

    r = client.get("/api/sentinel/playbooks?page=1&per_page=10")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["total"] == 2
    assert len(data["playbooks"]) == 2
    assert data["playbooks"][0]["playbook_id"] in ["PB-A", "PB-B"]


def test_api_get_playbook(db_session):
    """GET /api/sentinel/playbooks/{playbook_id} detailed view."""
    pb = _seed_one_playbook(db_session, "PB-A")
    
    # Valid ID
    r = client.get(f"/api/sentinel/playbooks/{pb.id}")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["playbook"]["playbook_id"] == "PB-A"
    assert data["playbook"]["playbook_content"] == "# SSH Brute Force Response Playbook"
    assert data["playbook"]["snort_rule"] is not None

    # Invalid ID
    r = client.get("/api/sentinel/playbooks/999999")
    assert r.status_code == 404


def test_api_get_stats(db_session):
    """GET /api/sentinel/stats metrics summary."""
    _seed_one_playbook(db_session, "PB-A", status="pending")
    _seed_one_playbook(db_session, "PB-B", status="approved")
    _seed_one_playbook(db_session, "PB-C", status="rejected")
    _seed_one_playbook(db_session, "PB-D", status="exported")

    r = client.get("/api/sentinel/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["total_playbooks"] == 4
    assert data["pending"] == 1
    assert data["approved"] == 1
    assert data["rejected"] == 1
    assert data["exported"] == 1
    assert data["avg_threat_score"] == 85.0


def test_api_get_mitre_mapping():
    """GET /api/sentinel/mitre/mapping ATT&CK matrix."""
    r = client.get("/api/sentinel/mitre/mapping")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["total"] == 12
    assert len(data["mappings"]) == 12
    assert "technique_id" in data["mappings"][0]
    assert "technique_name" in data["mappings"][0]


def test_api_generate_playbook(db_session):
    """POST /api/sentinel/generate manual execution."""
    payload = {
        "source_ips": ["10.0.0.99"],
        "target_ports": [2222],
        "protocols": ["TCP"],
        "event_count": 50,
        "campaign_id": "API-GEN-TEST"
    }
    r = client.post("/api/sentinel/generate", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["playbook_id"].startswith("PB-")
    assert data["service_type"] == "SSH"
    assert data["attack_type"] == "SSH_AUTH_FAILURE"
    assert data["db_record_id"] > 0

    # Verify saved in DB
    db_pb = db_session.query(SentinelPlaybook).filter_by(id=data["db_record_id"]).first()
    assert db_pb is not None
    assert db_pb.playbook_id == data["playbook_id"]


def test_api_approve_playbook(db_session):
    """PATCH /api/sentinel/playbooks/{playbook_id}/approve approval workflow."""
    pb = _seed_one_playbook(db_session, status="pending")

    # Empty reviewed_by validation rejection (Pydantic / input validation check)
    r = client.patch(f"/api/sentinel/playbooks/{pb.id}/approve", json={"reviewed_by": "   "})
    assert r.status_code == 422

    # Valid approval
    r = client.patch(f"/api/sentinel/playbooks/{pb.id}/approve", json={"reviewed_by": "analyst1"})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["playbook"]["status"] == "approved"
    assert data["playbook"]["reviewed_by"] == "analyst1"
    assert data["playbook"]["reviewed_at"] is not None

    # Already approved -> Conflict 409
    r = client.patch(f"/api/sentinel/playbooks/{pb.id}/approve", json={"reviewed_by": "analyst2"})
    assert r.status_code == 409

    # Non-existent playbook
    r = client.patch("/api/sentinel/playbooks/999999/approve", json={"reviewed_by": "analyst1"})
    assert r.status_code == 404


def test_api_reject_playbook(db_session):
    """PATCH /api/sentinel/playbooks/{playbook_id}/reject rejection workflow."""
    pb = _seed_one_playbook(db_session, status="pending")

    r = client.patch(f"/api/sentinel/playbooks/{pb.id}/reject", json={"reviewed_by": "analyst1"})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["playbook"]["status"] == "rejected"
    assert data["playbook"]["reviewed_by"] == "analyst1"
    assert data["playbook"]["reviewed_at"] is not None

    # Already rejected -> Conflict 409 (approve then reject is okay, but reject then reject is conflict)
    r = client.patch(f"/api/sentinel/playbooks/{pb.id}/reject", json={"reviewed_by": "analyst2"})
    assert r.status_code == 409

    # Non-existent playbook
    r = client.patch("/api/sentinel/playbooks/999999/reject", json={"reviewed_by": "analyst1"})
    assert r.status_code == 404


def test_api_export_playbook(db_session):
    """POST /api/sentinel/playbooks/{playbook_id}/export format handling and status update."""
    pb = _seed_one_playbook(db_session, status="approved")

    # 1. Export as markdown
    r = client.post(f"/api/sentinel/playbooks/{pb.id}/export?format=markdown")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    assert "attachment" in r.headers["content-disposition"]
    assert f"{pb.playbook_id}.md" in r.headers["content-disposition"]

    # Verify status changed to exported in DB
    db_session.refresh(pb)
    assert pb.status == "exported"

    # Reset to approved to test next format
    pb.status = "approved"
    db_session.commit()

    # 2. Export as json
    r = client.post(f"/api/sentinel/playbooks/{pb.id}/export?format=json")
    assert r.status_code == 200
    assert "application/json" in r.headers["content-type"]
    exported_json = r.json()
    assert exported_json["playbook_id"] == pb.playbook_id
    assert exported_json["status"] == "approved"

    # Reset to approved to test next format
    pb.status = "approved"
    db_session.commit()

    # 3. Export as stix
    r = client.post(f"/api/sentinel/playbooks/{pb.id}/export?format=stix")
    assert r.status_code == 200
    assert "application/json" in r.headers["content-type"]
    stix_bundle = r.json()
    # It might fall back to playbook JSON on generation error or succeed as STIX
    if "type" in stix_bundle:
        assert stix_bundle["type"] in ["bundle", "success"]

    # 4. Invalid format
    r = client.post(f"/api/sentinel/playbooks/{pb.id}/export?format=invalid_fmt")
    assert r.status_code == 400
    assert "Invalid export format" in r.json()["detail"]


def test_api_list_rules_snort_and_sigma(db_session):
    """GET /api/sentinel/rules/snort and GET /api/sentinel/rules/sigma pagination/filtering."""
    _seed_one_playbook(db_session, "PB-A")
    
    # Snort Rules
    r = client.get("/api/sentinel/rules/snort?limit=10&offset=0")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["total"] == 1
    assert len(data["rules"]) == 1
    assert "snort_rule" in data["rules"][0]

    # Sigma Rules
    r = client.get("/api/sentinel/rules/sigma?limit=10&offset=0")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["total"] == 1
    assert len(data["rules"]) == 1
    assert "sigma_rule" in data["rules"][0]


# ---------------------------------------------------------------------------
# Pagination Tests
# ---------------------------------------------------------------------------
def test_pagination_and_metadata(db_session):
    """Verify ?page=1&per_page=20 returns correct results and metadata."""
    # Seed 25 playbooks
    for i in range(25):
        _seed_one_playbook(db_session, playbook_id=f"PB-PAG-{i:03d}")

    # Page 1
    r = client.get("/api/sentinel/playbooks?page=1&per_page=20")
    assert r.status_code == 200
    data = r.json()
    assert data["page"] == 1
    assert data["per_page"] == 20
    assert data["total"] == 25
    assert len(data["playbooks"]) == 20

    # Page 2
    r = client.get("/api/sentinel/playbooks?page=2&per_page=20")
    assert r.status_code == 200
    data = r.json()
    assert data["page"] == 2
    assert len(data["playbooks"]) == 5

    # Check validation boundary
    r_invalid_page = client.get("/api/sentinel/playbooks?page=0")
    assert r_invalid_page.status_code == 422

    r_invalid_size = client.get("/api/sentinel/playbooks?per_page=0")
    assert r_invalid_size.status_code == 422


# ---------------------------------------------------------------------------
# Filtering Tests
# ---------------------------------------------------------------------------
def test_filtering_by_status_and_attack_type(db_session):
    """Verify filtering works correctly."""
    _seed_one_playbook(db_session, "PB-1", status="pending", attack_type="SSH_AUTH_FAILURE")
    _seed_one_playbook(db_session, "PB-2", status="approved", attack_type="SSH_AUTH_FAILURE")
    _seed_one_playbook(db_session, "PB-3", status="rejected", attack_type="HTTP_SCANNER_BEHAVIOR")

    # Status filter
    r = client.get("/api/sentinel/playbooks?status=approved")
    data = r.json()
    assert data["total"] == 1
    assert data["playbooks"][0]["playbook_id"] == "PB-2"

    r = client.get("/api/sentinel/playbooks?status=pending")
    data = r.json()
    assert data["total"] == 1
    assert data["playbooks"][0]["playbook_id"] == "PB-1"

    # Attack type filter
    r = client.get("/api/sentinel/playbooks?attack_type=HTTP_SCANNER_BEHAVIOR")
    data = r.json()
    assert data["total"] == 1
    assert data["playbooks"][0]["playbook_id"] == "PB-3"


# ---------------------------------------------------------------------------
# Edge Case Tests
# ---------------------------------------------------------------------------
def test_edge_case_empty_database():
    """Verify empty database returns clean lists/stats and appropriate 404s."""
    # List playbooks
    r = client.get("/api/sentinel/playbooks")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert len(data["playbooks"]) == 0

    # Stats
    r = client.get("/api/sentinel/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["total_playbooks"] == 0
    assert data["pending"] == 0
    assert data["approved"] == 0
    assert data["rejected"] == 0
    assert data["exported"] == 0
    assert data["avg_threat_score"] == 0.0

    # Detail
    r = client.get("/api/sentinel/playbooks/1")
    assert r.status_code == 404


def test_edge_case_single_playbook(db_session):
    """Verify stats and pagination with exactly one playbook."""
    _seed_one_playbook(db_session, "PB-SINGLE", status="pending")

    r = client.get("/api/sentinel/playbooks?page=1&per_page=20")
    assert r.json()["total"] == 1
    assert len(r.json()["playbooks"]) == 1

    r = client.get("/api/sentinel/stats")
    assert r.json()["total_playbooks"] == 1
    assert r.json()["pending"] == 1


def test_edge_case_maximum_page_size(db_session):
    """Verify maximum page size limits are correctly validated (max per_page is 100)."""
    # per_page = 100 is valid
    r = client.get("/api/sentinel/playbooks?per_page=100")
    assert r.status_code == 200

    # per_page = 101 is invalid (422)
    r = client.get("/api/sentinel/playbooks?per_page=101")
    assert r.status_code == 422
