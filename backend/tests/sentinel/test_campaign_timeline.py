import os
import sys
import pytest
from datetime import datetime, timedelta

# Ensure backend directory is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

os.environ["DATABASE_URL"] = "sqlite:///./phantomnet.db"

from fastapi import FastAPI
from fastapi.testclient import TestClient
from api.sentinel import router as sentinel_router
from database.database import Base, engine, SessionLocal
from sentinel.models import SentinelPlaybook
from database.models import PacketLog

app = FastAPI()
app.include_router(sentinel_router)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.database import get_db

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_timeline.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

from middleware.auth import get_current_user
from database.models import User

def mock_get_current_user():
    return User(id=1, username="testadmin", role="admin", status="active")

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = mock_get_current_user
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    pb = SentinelPlaybook(
        playbook_id="CAMP-TIMELINE-001",
        status="approved",
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        dst_port=2222,
        protocol="TCP",
        src_ip="10.9.8.7",
        playbook_name="Timeline Test",
    )
    db.add(pb)
    
    # Add packet logs for timeline
    base_time = datetime(2026, 8, 1, 10, 0, 0)
    
    for _ in range(3):
        db.add(PacketLog(timestamp=base_time + timedelta(minutes=5), src_ip="10.9.8.7", dst_port=2222, protocol="TCP"))
    for _ in range(5):
        db.add(PacketLog(timestamp=base_time + timedelta(hours=1, minutes=10), src_ip="10.9.8.7", dst_port=2222, protocol="TCP"))
    for _ in range(2):
        db.add(PacketLog(timestamp=base_time + timedelta(days=1, hours=2), src_ip="10.9.8.7", dst_port=2222, protocol="TCP"))

    db.commit()
    db.close()
    
    yield
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_campaign_timeline_hourly(client):
    db = TestingSessionLocal()
    pb = db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id == "CAMP-TIMELINE-001").first()
    print("DEBUG PB:", pb)
    db.close()
    res = client.get("/api/sentinel/campaigns/CAMP-TIMELINE-001/timeline?interval=hourly")
    print("DEBUG RES:", res.json())
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["campaign_id"] == "CAMP-TIMELINE-001"
    assert data["interval"] == "hourly"
    assert data["total_events"] == 10
    
    timeline = data["timeline"]
    assert len(timeline) == 3
    
    assert timeline[0]["timestamp"] == "2026-08-01 10:00:00"
    assert timeline[0]["count"] == 3
    
    assert timeline[1]["timestamp"] == "2026-08-01 11:00:00"
    assert timeline[1]["count"] == 5

    assert timeline[2]["timestamp"] == "2026-08-02 12:00:00"
    assert timeline[2]["count"] == 2

def test_campaign_timeline_daily(client):
    res = client.get("/api/sentinel/campaigns/CAMP-TIMELINE-001/timeline?interval=daily")
    assert res.status_code == 200
    data = res.json()
    assert data["interval"] == "daily"
    assert data["total_events"] == 10
    
    timeline = data["timeline"]
    assert len(timeline) == 2
    
    assert timeline[0]["timestamp"] == "2026-08-01 00:00:00"
    assert timeline[0]["count"] == 8
    
    assert timeline[1]["timestamp"] == "2026-08-02 00:00:00"
    assert timeline[1]["count"] == 2

def test_campaign_timeline_not_found(client):
    res = client.get("/api/sentinel/campaigns/INVALID-CAMP/timeline")
    assert res.status_code == 404
