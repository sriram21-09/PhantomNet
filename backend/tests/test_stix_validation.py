"""
backend/tests/test_stix_validation.py
---------------------------------------
STIX 2.1 schema validation test suite using the official python `stix2` library.
Validates that STIX bundles and SDOs served by the TAXII server comply with STIX 2.1 specs.
"""

import os
import sys
import uuid
import pytest
from datetime import datetime

# Ensure backend directory is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from sentinel.models import SentinelPlaybook
from database.database import Base, engine, SessionLocal
import stix2
from fastapi import FastAPI
from fastapi.testclient import TestClient
from api.taxii import router as taxii_router, get_taxii_user
from database.models import User

app = FastAPI()
app.include_router(taxii_router)
app.dependency_overrides[get_taxii_user] = lambda: User(username="testuser", role="Admin", status="active")


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Clean prior test playbooks
    db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id.like("PB-STIX-VAL-%")).delete(synchronize_session=False)
    db.commit()

    pb1 = SentinelPlaybook(
        playbook_id="PB-STIX-VAL-001",
        status="approved",
        tactic="Credential Access",
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        dst_port=22,
        protocol="TCP",
        src_ip="192.168.1.100",
        threat_score=85.0,
        severity="HIGH",
        playbook_name="SSH Brute Force Response",
        playbook_content="## Playbook: SSH Brute Force\nBlock source IP.",
        created_at=datetime(2026, 3, 15, 10, 0, 0),
        updated_at=datetime(2026, 3, 15, 10, 0, 0),
    )
    pb2 = SentinelPlaybook(
        playbook_id="PB-STIX-VAL-002",
        status="approved",
        tactic="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        dst_port=80,
        protocol="TCP",
        src_ip="10.0.0.50",
        threat_score=92.0,
        severity="CRITICAL",
        playbook_name="Web Exploit Detection",
        playbook_content="## Playbook: Web Exploit\nAnalyze HTTP payloads.",
        created_at=datetime(2026, 6, 20, 14, 30, 0),
        updated_at=datetime(2026, 6, 20, 14, 30, 0),
    )
    db.add(pb1)
    db.add(pb2)
    db.commit()
    db.close()
    yield
    db = SessionLocal()
    db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id.like("PB-STIX-VAL-%")).delete(synchronize_session=False)
    db.commit()
    db.close()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_stix_bundle_validation(client):
    res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/")
    assert res.status_code == 200
    bundle_data = res.json()

    # Validate bundle schema using python stix2 parser
    parsed_bundle = stix2.parse(bundle_data, allow_custom=True)
    assert parsed_bundle.type == "bundle"
    assert len(parsed_bundle.objects) > 0
