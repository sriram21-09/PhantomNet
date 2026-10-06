"""
tests/noc/conftest.py
---------------------
Pytest configuration and shared fixtures for Neural Operations Center (NOC) tests.
Ensures clean database state, authentication headers, and seed packet logs.
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

os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "a" * 32
os.environ["HONEYPOT_SECRET_KEY"] = "b" * 32

from main import app
from database.database import get_db
from database.models import Base, User, PacketLog
from middleware.auth import hash_password, create_access_token


@pytest.fixture(scope="session")
def noc_db_file():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="phantomnet_noc_test_")
    os.close(fd)
    yield path
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


@pytest.fixture(scope="session")
def noc_engine(noc_db_file):
    engine = create_engine(
        f"sqlite:///{noc_db_file}",
        connect_args={"check_same_thread": False},
        poolclass=NullPool
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def TestingSessionLocal(noc_engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=noc_engine)


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
def seed_test_users(noc_engine, TestingSessionLocal):
    session = TestingSessionLocal()
    session.query(User).delete()
    user = User(
        username="noc_operator",
        email="noc_operator@phantomnet.local",
        hashed_password=hash_password("NocPassword123!"),
        role="Analyst",
        created_at=datetime.now(timezone.utc)
    )
    session.add(user)
    session.commit()
    session.close()


@pytest.fixture
def auth_token():
    return create_access_token(data={"sub": "noc_operator", "role": "Analyst"})


@pytest.fixture
def auth_headers(auth_token):
    return {
        "Authorization": f"Bearer {auth_token}",
        "Origin": "http://localhost:3000"
    }


@pytest.fixture
def auth_cookies(auth_token):
    return {
        "phantomnet_access_token": auth_token
    }


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seed_packets(TestingSessionLocal):
    session = TestingSessionLocal()
    session.query(PacketLog).delete()
    now = datetime.utcnow()

    packets = [
        # Attacker 1: 192.168.1.100 (HIGH severity activity)
        PacketLog(
            timestamp=now - timedelta(minutes=10),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=44210,
            dst_port=22,
            protocol="SSH",
            attack_type="MALICIOUS",
            threat_level="HIGH",
            threat_score=0.75,
            length=120
        ),
        PacketLog(
            timestamp=now - timedelta(minutes=8),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=44212,
            dst_port=22,
            protocol="SSH",
            attack_type="MALICIOUS",
            threat_level="CRITICAL",
            threat_score=0.85,
            length=135
        ),
        # Attacker 2: 192.168.1.200 (LOW/BENIGN traffic)
        PacketLog(
            timestamp=now - timedelta(minutes=5),
            src_ip="192.168.1.200",
            dst_ip="10.0.0.1",
            src_port=52300,
            dst_port=80,
            protocol="TCP",
            attack_type="BENIGN",
            threat_level="LOW",
            threat_score=0.25,
            length=64
        ),
    ]
    session.add_all(packets)
    session.commit()
    yield
    session.query(PacketLog).delete()
    session.commit()
    session.close()
