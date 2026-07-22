import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))
import pytest
from sqlalchemy.orm import Session
from database.database import SessionLocal, engine
from database.models import Base
from sentinel.models import SentinelPlaybook
from sentinel.mitre_matrix import (
    get_mitre_matrix_config,
    get_playbook_counts_by_technique,
    get_aggregated_matrix_data
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
    assert any(tech["technique_id"] == "T1110.001" for tech in config["Credential Access"])

def test_aggregation_counts(db_session: Session):
    # Insert test data: 3 playbooks for T1110.001 and 1 playbook for T1190
    playbooks = [
        SentinelPlaybook(playbook_id="PB-001", technique_id="T1110.001", status="pending"),
        SentinelPlaybook(playbook_id="PB-002", technique_id="T1110.001", status="pending"),
        SentinelPlaybook(playbook_id="PB-003", technique_id="T1110.001", status="pending"),
        SentinelPlaybook(playbook_id="PB-004", technique_id="T1190", status="pending"),
        SentinelPlaybook(playbook_id="PB-005", technique_id=None, status="pending") # should be ignored
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
