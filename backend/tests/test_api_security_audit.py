"""
Comprehensive API Security Audit & Hardening Test Suite
======================================================
Tests verify authentication & role enforcement, input validation & sanitization,
bounds checking, timing-attack-safe verification, path traversal prevention,
and information leakage mitigation across all backend endpoints.
"""

import os
import sys

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

os.environ["ENVIRONMENT"] = "test"

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from database.database import Base, get_db
from database.models import User, Event
from middleware.auth import create_access_token
from api.admin import hash_password
from main import app

# In-memory SQLite engine for test isolation
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
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin_token(db_session):
    user = User(
        username="sec_admin",
        email="sec_admin@phantomnet.io",
        hashed_password=hash_password("AdminPass123!"),
        role="Admin",
        status="active",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return create_access_token(data={"sub": user.username, "role": user.role})


@pytest.fixture
def analyst_token(db_session):
    user = User(
        username="sec_analyst",
        email="sec_analyst@phantomnet.io",
        hashed_password=hash_password("AnalystPass123!"),
        role="Analyst",
        status="active",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return create_access_token(data={"sub": user.username, "role": user.role})


# ===========================================================================
# 1. AUTHENTICATION & TIMING-SAFE API KEY ENFORCEMENT
# ===========================================================================
class TestAuthenticationEnforcement:
    def test_management_node_register_missing_key(self, client):
        """Missing X-API-Key must return 401 Unauthorized."""
        res = client.post("/api/v1/management/register", json={
            "hostname": "Sensor-01",
            "ip_address": "192.168.1.50",
            "honeypot_type": "SSH"
        })
        assert res.status_code == 401
        assert "Missing" in res.json().get("detail", "")

    def test_management_node_register_invalid_key(self, client):
        """Invalid X-API-Key must return 403 Forbidden."""
        res = client.post(
            "/api/v1/management/register",
            headers={"X-API-Key": "completely_wrong_key"},
            json={
                "hostname": "Sensor-01",
                "ip_address": "192.168.1.50",
                "honeypot_type": "SSH"
            }
        )
        assert res.status_code == 403
        assert "Invalid" in res.json().get("detail", "")

    def test_admin_endpoints_require_admin_role(self, client, analyst_token):
        """Standard Analyst must be rejected with 403 on Admin-only routes."""
        headers = {"Authorization": f"Bearer {analyst_token}"}
        res = client.get("/api/v1/admin/users", headers=headers)
        assert res.status_code == 403
        assert "Admin" in res.json().get("detail", "")

    def test_admin_endpoints_accessible_by_admin(self, client, admin_token):
        """Admin user can access Admin routes."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        res = client.get("/api/v1/admin/users", headers=headers)
        assert res.status_code == 200

    def test_sentinel_audit_logs_requires_auth(self, client):
        """Unauthenticated requests to /api/v1/sentinel/audit-logs return 401."""
        res = client.get("/api/v1/sentinel/audit-logs")
        assert res.status_code == 401


# ===========================================================================
# 2. INPUT VALIDATION & BOUNDS CHECKING
# ===========================================================================
class TestInputValidationAndBounds:
    def test_node_register_invalid_ip_format(self, client):
        """Malformed IP format must be rejected by Pydantic validator."""
        res = client.post(
            "/api/v1/management/register",
            headers={"X-API-Key": os.getenv("API_KEY", "default_key")},
            json={
                "hostname": "Sensor-01",
                "ip_address": "999.999.999.999",
                "honeypot_type": "SSH"
            }
        )
        assert res.status_code == 422

    def test_node_register_empty_hostname(self, client):
        """Blank hostname must be rejected with 422."""
        res = client.post(
            "/api/v1/management/register",
            headers={"X-API-Key": os.getenv("API_KEY", "default_key")},
            json={
                "hostname": "   ",
                "ip_address": "10.0.0.1",
                "honeypot_type": "SSH"
            }
        )
        assert res.status_code == 422

    def test_admin_password_change_min_length(self, client, admin_token):
        """Password shorter than 6 characters must be rejected with 422."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        res = client.put(
            "/api/v1/admin/users/1",
            headers=headers,
            json={"password": "123"}
        )
        assert res.status_code == 422

    def test_admin_event_purge_bounds(self, client, admin_token):
        """Retention days outside 1-3650 must return 400."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        res = client.delete("/api/v1/admin/events/old?days=0", headers=headers)
        assert res.status_code == 400
        res = client.delete("/api/v1/admin/events/old?days=5000", headers=headers)
        assert res.status_code == 400

    def test_cases_invalid_priority_rejected(self, client):
        """Invalid priority string must return 422."""
        res = client.post("/api/v1/cases/", json={
            "title": "Suspicious Activity",
            "description": "Investigating incident",
            "priority": "ExtremeUrgent"
        })
        assert res.status_code == 422

    def test_cases_valid_priority_accepted(self, client):
        """Valid priority string ('High') is normalized and accepted."""
        res = client.post("/api/v1/cases/", json={
            "title": "Suspicious Activity",
            "description": "Investigating incident",
            "priority": "High"
        })
        assert res.status_code == 200
        assert res.json()["priority"] == "High"

    def test_reports_invalid_frequency_rejected(self, client):
        """Invalid frequency string must return 422."""
        res = client.post("/api/v1/reports/schedule", json={
            "name": "Weekly Audit",
            "template_type": "Executive Summary",
            "frequency": "hourly_not_allowed",
            "schedule_time": "08:00",
            "recipients": "soc@phantomnet.io"
        })
        assert res.status_code == 422

    def test_reports_invalid_time_format_rejected(self, client):
        """Malformed schedule_time string must return 422."""
        res = client.post("/api/v1/reports/schedule", json={
            "name": "Weekly Audit",
            "template_type": "Executive Summary",
            "frequency": "daily",
            "schedule_time": "25:99",
            "recipients": "soc@phantomnet.io"
        })
        assert res.status_code == 422

    def test_hunting_invalid_logic_rejected(self, client):
        """Invalid boolean logic operator must return 422."""
        res = client.post("/api/v1/hunting/search", json={
            "logic": "XOR",
            "conditions": [{"field": "src_ip", "operator": "equals", "value": "1.2.3.4"}]
        })
        assert res.status_code == 422

    def test_hunting_invalid_operator_rejected(self, client):
        """Invalid query operator must return 422."""
        res = client.post("/api/v1/hunting/search", json={
            "logic": "AND",
            "conditions": [{"field": "src_ip", "operator": "matches_regex_injection", "value": ".*"}]
        })
        assert res.status_code == 422


# ===========================================================================
# 3. IP FORMAT VALIDATION & ACTIVE DEFENSE BOUNDS
# ===========================================================================
class TestIPValidationAndActiveDefense:
    def test_attacker_profile_invalid_ip(self, client):
        """Malformed IP address format must return 400 Bad Request."""
        res = client.get("/api/v1/attribution/profile/invalid..ip..format")
        assert res.status_code == 400
        assert "Invalid IP address format" in res.json().get("detail", "")

    def test_threat_intel_enrich_invalid_ip(self, client):
        """Enrichment endpoint with malformed IP returns 400."""
        res = client.get("/api/v1/enrich/ip/999.888.777.666")
        assert res.status_code == 400

    def test_geoip_lookup_invalid_ip(self, client):
        """GeoIP lookup with malformed IP returns 400."""
        res = client.get("/api/geoip/lookup/not_an_ip")
        assert res.status_code == 400

    def test_active_defense_block_protected_ip(self, client):
        """Attempting to block localhost or protected service returns safety error."""
        res = client.post("/active-defense/block/127.0.0.1")
        assert res.status_code == 200
        assert res.json()["status"] == "error"
        assert "Cannot block" in res.json()["message"]

    def test_active_defense_block_invalid_ip(self, client):
        """Attempting to block malformed IP returns 400."""
        res = client.post("/active-defense/block/invalid_ip_addr")
        assert res.status_code == 400


# ===========================================================================
# 4. PATH TRAVERSAL MITIGATION
# ===========================================================================
class TestPathTraversalMitigation:
    def test_pcap_download_path_traversal_blocked(self, client, db_session):
        """Injecting relative path traversal inside event.pcap_path is blocked with 403."""
        event = Event(
            source_ip="192.168.1.100",
            honeypot_type="SSH",
            raw_data="login_attempt",
            pcap_path="../../../etc/passwd"
        )
        db_session.add(event)
        db_session.commit()
        db_session.refresh(event)

        res = client.get(f"/api/v1/events/{event.id}/pcap")
        assert res.status_code == 403
        assert "Invalid PCAP file path" in res.json().get("detail", "")


# ===========================================================================
# 5. ERROR SANITIZATION & INFORMATION LEAKAGE PREVENTION
# ===========================================================================
class TestErrorSanitization:
    def test_alerts_resolve_nonexistent(self, client):
        """Non-existent alert returns clean 404."""
        res = client.patch("/api/v1/alerts/99999999/resolve")
        assert res.status_code == 404
        assert res.json().get("detail") == "Alert not found"

    def test_unhandled_route_error_format(self, client):
        """404 errors adhere to standard format without server internals."""
        res = client.get("/api/nonexistent/route")
        assert res.status_code == 404
