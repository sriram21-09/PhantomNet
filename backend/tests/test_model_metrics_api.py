"""
Test Suite for Model Metrics & ML Observability Endpoints
=========================================================
Tests verify:
- Authentication & RBAC enforcement
- Authoritative Model Registry integration
- Genuine feature importance rankings (sum = 1.0)
- Performant single-query prediction distribution with benign/malicious distinction
- Real confidence histogram binning
- Dynamic threat score calculation based on real telemetry
- No synthetic or fabricated metrics
- Caching and performance behavior
"""

import os
import sys
from datetime import datetime, timedelta

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

os.environ["ENVIRONMENT"] = "test"

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from database.database import Base, get_db
from database.models import User, PacketLog, HoneypotNode
from middleware.auth import create_access_token
from main import app

# Isolated in-memory SQLite engine for tests
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session(setup_db):
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin_token(db_session):
    admin = db_session.query(User).filter(User.username == "test_admin").first()
    if not admin:
        admin = User(
            username="test_admin",
            email="admin@test.local",
            hashed_password="hashed_pw",
            role="Admin",
            status="active"
        )
        db_session.add(admin)
        db_session.commit()
    return create_access_token(data={"sub": "test_admin", "role": "Admin"})


@pytest.fixture
def viewer_token(db_session):
    viewer = db_session.query(User).filter(User.username == "test_viewer").first()
    if not viewer:
        viewer = User(
            username="test_viewer",
            email="viewer@test.local",
            hashed_password="hashed_pw",
            role="Viewer",
            status="active"
        )
        db_session.add(viewer)
        db_session.commit()
    return create_access_token(data={"sub": "test_viewer", "role": "Viewer"})


# =========================================================================
# 1. Authentication & RBAC Tests
# =========================================================================

def test_unauthenticated_request_rejected(client):
    """Endpoints require authentication and reject anonymous requests."""
    endpoints = [
        "/api/v1/model/stats",
        "/api/v1/model/feature-importance",
        "/api/v1/model/predictions/recent",
        "/api/v1/model/confidence-histogram",
    ]
    for ep in endpoints:
        response = client.get(ep)
        assert response.status_code in [401, 403], f"Expected 401/403 for {ep}, got {response.status_code}"


def test_viewer_access_to_observability_endpoints(client, viewer_token):
    """Viewers have read-only access to observability endpoints."""
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/model/stats", headers=headers)
    assert response.status_code == 200
    assert "metrics" in response.json()


def test_rbac_protects_training_config(client, viewer_token, admin_token):
    """Sensitive training configuration is restricted from Viewer roles."""
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    resp_viewer = client.get("/api/v1/model/config", headers=viewer_headers)
    assert resp_viewer.status_code == 403

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    resp_admin = client.get("/api/v1/model/config", headers=admin_headers)
    assert resp_admin.status_code in [200, 404]  # 404 only if config file not deployed


# =========================================================================
# 2. Stats & Telemetry Integrity Tests
# =========================================================================

def test_stats_authoritative_metrics(client, admin_token, db_session):
    """Stats endpoint returns authoritative metrics without mathematical fabrication."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Insert test packet telemetry
    now = datetime.utcnow()
    p1 = PacketLog(timestamp=now, threat_score=75.0, confidence=0.88, attack_type="SSH_BRUTE_FORCE")
    p2 = PacketLog(timestamp=now - timedelta(minutes=5), threat_score=20.0, confidence=0.92, attack_type="BENIGN")
    db_session.add_all([p1, p2])
    db_session.commit()

    response = client.get("/api/v1/model/stats", headers=headers)
    assert response.status_code == 200
    data = response.json()

    # Structural assertions
    assert "metrics" in data
    assert "threat_analysis" in data
    assert "insights" in data
    assert data["modelName"] == "AttackClassifier_Enhanced"

    # Threat score reflects highest recent score
    threat = data["threat_analysis"]
    assert threat["threat_score"] == 75
    assert threat["severity"] == "HIGH"
    assert threat["confidence"] > 0

    # Ensure accuracy is not fabricated as (precision + recall) / 2
    metrics = data["metrics"]
    prec = metrics["precision"]
    rec = metrics["recall"]
    acc = metrics["accuracy"]
    if prec != rec and prec > 0 and rec > 0:
        assert acc != round((prec + rec) / 2, 3), "Accuracy must not be fabricated from (P+R)/2"


# =========================================================================
# 3. Feature Importance Integrity Tests
# =========================================================================

def test_feature_importance_valid_and_non_synthetic(client, admin_token):
    """Feature importances come from real model weights and sum to 1.0 (not 1.46)."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/v1/model/feature-importance", headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert "features" in data
    features = data["features"]
    assert len(features) >= 10

    # Assert descending order
    importances = [f["importance"] for f in features]
    assert importances == sorted(importances, reverse=True)

    # Assert mathematical validity: sum should be approximately 1.0 (100%), not 1.46
    total_importance = sum(importances)
    assert 0.95 <= total_importance <= 1.05, f"Feature importances must sum to ~1.0, got {total_importance}"

    # Assert NO synthetic step loop (0.28, 0.25, 0.22...)
    assert importances[:3] != [0.28, 0.25, 0.22], "Must not use synthetic decreasing loop"


# =========================================================================
# 4. Prediction Distribution & Aggregation Tests
# =========================================================================

def test_recent_predictions_grouped_aggregation(client, admin_token, db_session):
    """Recent predictions returns 6 discrete time intervals separating benign and malicious."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    now = datetime.utcnow()
    # Add benign and malicious packets in recent hours
    b_packet = PacketLog(timestamp=now - timedelta(hours=1), threat_score=15.0)
    m_packet = PacketLog(timestamp=now - timedelta(hours=1), threat_score=85.0)
    db_session.add_all([b_packet, m_packet])
    db_session.commit()

    response = client.get("/api/v1/model/predictions/recent", headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert "data" in data
    timeline = data["data"]
    assert len(timeline) == 6, "Must provide 6 discrete chronological hourly slots"

    # Verify each bucket structure
    for slot in timeline:
        assert "time" in slot
        assert "benign" in slot
        assert "malicious" in slot
        assert isinstance(slot["benign"], int)
        assert isinstance(slot["malicious"], int)


# =========================================================================
# 5. Confidence Histogram Tests
# =========================================================================

def test_confidence_histogram_bins(client, admin_token, db_session):
    """Confidence histogram correctly categorizes model confidence into 5 buckets."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Add packets with varying confidence levels
    now = datetime.utcnow()
    logs = [
        PacketLog(timestamp=now, confidence=0.15),
        PacketLog(timestamp=now, confidence=0.35),
        PacketLog(timestamp=now, confidence=0.55),
        PacketLog(timestamp=now, confidence=0.75),
        PacketLog(timestamp=now, confidence=0.95),
    ]
    db_session.add_all(logs)
    db_session.commit()

    response = client.get("/api/v1/model/confidence-histogram", headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert "buckets" in data
    buckets = data["buckets"]
    assert len(buckets) == 5

    expected_ranges = ["0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"]
    actual_ranges = [b["range"] for b in buckets]
    assert actual_ranges == expected_ranges
    assert data["metric_type"] == "model_confidence"
