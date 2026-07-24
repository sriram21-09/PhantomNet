import os
import sys

# Force SQLite test database configuration before importing database models
os.environ["DATABASE_URL"] = "sqlite:///./phantomnet.db"
os.environ["ENVIRONMENT"] = "test"

# Ensure backend and root project directories are in sys.path
dir_path = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(dir_path, ".."))
backend_dir = os.path.join(root_dir, "backend")

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# pyrefly: ignore [missing-import]
import pytest
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import Session
# pyrefly: ignore [missing-import]
from database.database import SessionLocal, engine, get_db
# pyrefly: ignore [missing-import]
from database.models import Base
# pyrefly: ignore [missing-import]
from sentinel.models import SentinelPlaybook
# pyrefly: ignore [missing-import]
from sentinel.mitre_matrix import (
    get_mitre_matrix_config,
    get_playbook_counts_by_technique,
    get_aggregated_matrix_data,
    build_matrix_response,
)


@pytest.fixture(scope="module")
def db_session():
    # Setup the test database
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()

    # Cleanup any existing records
    session.query(SentinelPlaybook).delete()
    session.commit()

    yield session

    # Teardown
    session.query(SentinelPlaybook).delete()
    session.commit()
    session.close()


def test_get_mitre_matrix_config():
    config = get_mitre_matrix_config()
    # It should have 9 unique tactics based on the 12 techniques mapped
    assert len(config) == 9
    assert "Credential Access" in config
    assert "Initial Access" in config

    # Check T1110.001 is mapped under Credential Access
    ca_techs = config["Credential Access"]
    assert any(tech["technique_id"] == "T1110.001" for tech in ca_techs)

    # Verify technique object metadata fields
    sample_tech = ca_techs[0]
    for key in ["technique_id", "technique_name", "tactic_id", "severity", "url", "description"]:
        assert key in sample_tech


def test_aggregation_counts(db_session: Session):
    # Insert test data: 3 playbooks for T1110.001 and 1 playbook for T1190
    playbooks = [
        SentinelPlaybook(playbook_id="PB-001", technique_id="T1110.001", status="pending"),
        SentinelPlaybook(playbook_id="PB-002", technique_id="T1110.001", status="pending"),
        SentinelPlaybook(playbook_id="PB-003", technique_id="T1110.001", status="pending"),
        SentinelPlaybook(playbook_id="PB-004", technique_id="T1190", status="pending"),
        SentinelPlaybook(playbook_id="PB-005", technique_id=None, status="pending"),  # should be ignored
    ]
    db_session.add_all(playbooks)
    db_session.commit()

    # Validate db helper logic
    counts = get_playbook_counts_by_technique(db_session)
    assert counts.get("T1110.001") == 3
    assert counts.get("T1190") == 1
    assert counts.get("T1021.004") is None  # not present


def test_aggregated_matrix_data(db_session: Session):
    # Test the final aggregation
    data = get_aggregated_matrix_data(db_session)

    # T1110.001 is under Credential Access
    ca_techs = data["Credential Access"]
    t1110_001 = next(t for t in ca_techs if t["technique_id"] == "T1110.001")
    assert t1110_001["count"] == 3

    # T1190 is under Initial Access
    ia_techs = data["Initial Access"]
    t1190 = next(t for t in ia_techs if t["technique_id"] == "T1190")
    assert t1190["count"] == 1

    # T1021.004 under Lateral Movement should have count 0
    lm_techs = data["Lateral Movement"]
    t1021_004 = next(t for t in lm_techs if t["technique_id"] == "T1021.004")
    assert t1021_004["count"] == 0


def test_mitre_matrix_endpoint(db_session: Session):
    # pyrefly: ignore [missing-import]
    from fastapi import FastAPI
    # pyrefly: ignore [missing-import]
    from fastapi.testclient import TestClient
    # pyrefly: ignore [missing-import]
    from api.sentinel import router as sentinel_router

    app = FastAPI()
    # Override get_db dependency to use the active test session
    app.dependency_overrides[get_db] = lambda: db_session
    app.include_router(sentinel_router)

    with TestClient(app) as client:
        res = client.get("/api/sentinel/mitre/matrix")
        assert res.status_code == 200
        data = res.json()
        assert data.get("status") == "success"
        assert "matrix" in data
        assert "frequency_map" in data
        assert "generated_at" in data
        assert "total_tactics" in data
        assert "total_techniques" in data
        assert "Credential Access" in data["matrix"]
        assert "Initial Access" in data["matrix"]

        # Validate frequency_map rollups for populated techniques
        freq = data["frequency_map"]
        assert freq.get("T1110") == 3
        assert freq.get("T1190") == 1
