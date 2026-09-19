"""
tests/api/conftest.py
--------------------
Isolated testing fixtures for Phase 1 Authentication, RBAC, Token Lifecycle,
CSRF, Step-Up Defense, and TAXII endpoints.
"""
import os
import sys
import tempfile
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import sessionmaker

# Setup test environment before imports
os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "a" * 32  # Valid length test secret
os.environ["HONEYPOT_SECRET_KEY"] = "b" * 32

from main import app
from database.database import get_db
from database.models import (
    Base, User, TaxiiClient, AuditLog, RefreshToken,
    Alert, InvestigationCase, ScheduledReport, PacketLog
)
from middleware.auth import (
    hash_password, create_access_token, create_step_up_token
)


@pytest.fixture(scope="session")
def test_db_file():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="phantomnet_test_api_")
    os.close(fd)
    yield path
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


@pytest.fixture(scope="session")
def db_engine(test_db_file):
    engine = create_engine(
        f"sqlite:///{test_db_file}",
        connect_args={"check_same_thread": False},
        poolclass=NullPool
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def TestingSessionLocal(db_engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=db_engine)


@pytest.fixture
def db_session(TestingSessionLocal):
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(autouse=True)
def override_db(TestingSessionLocal):
    def _override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.rollback()
            session.close()

    app.dependency_overrides[get_db] = _override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture(scope="session", autouse=True)
def seed_test_users(db_engine, TestingSessionLocal):
    """Seed test users into test DB once for the test session."""
    session = TestingSessionLocal()
    
    # Clean prior users if any
    session.query(User).delete()
    session.query(TaxiiClient).delete()
    
    admin = User(
        username="admin_user",
        email="admin_user@phantomnet.local",
        hashed_password=hash_password("AdminPass123!"),
        role="Admin",
        created_at=datetime.now(timezone.utc)
    )
    analyst = User(
        username="analyst_user",
        email="analyst_user@phantomnet.local",
        hashed_password=hash_password("AnalystPass123!"),
        role="Analyst",
        created_at=datetime.now(timezone.utc)
    )
    viewer = User(
        username="viewer_user",
        email="viewer_user@phantomnet.local",
        hashed_password=hash_password("ViewerPass123!"),
        role="Viewer",
        created_at=datetime.now(timezone.utc)
    )
    session.add_all([admin, analyst, viewer])

    # Seed TAXII M2M Client
    taxii_client = TaxiiClient(
        client_name="SOC SIEM Collector",
        key_id="taxii-client-01",
        secret_hash=hash_password("SecretTaxiiPass123!"),
        scopes='["taxii:read"]',
        created_at=datetime.now(timezone.utc)
    )
    session.add(taxii_client)

    session.commit()
    session.close()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token():
    return create_access_token(data={"sub": "admin_user", "role": "Admin"})


@pytest.fixture
def analyst_token():
    return create_access_token(data={"sub": "analyst_user", "role": "Analyst"})


@pytest.fixture
def viewer_token():
    return create_access_token(data={"sub": "viewer_user", "role": "Viewer"})


@pytest.fixture
def admin_headers(admin_token):
    return {
        "Authorization": f"Bearer {admin_token}",
        "X-CSRF-Token": "csrf-valid-token-123",
        "Origin": "http://localhost:3000"
    }


@pytest.fixture
def analyst_headers(analyst_token):
    return {
        "Authorization": f"Bearer {analyst_token}",
        "X-CSRF-Token": "csrf-valid-token-123",
        "Origin": "http://localhost:3000"
    }


@pytest.fixture
def viewer_headers(viewer_token):
    return {
        "Authorization": f"Bearer {viewer_token}",
        "X-CSRF-Token": "csrf-valid-token-123",
        "Origin": "http://localhost:3000"
    }


@pytest.fixture
def step_up_token():
    return create_step_up_token("admin_user")
