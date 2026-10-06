"""
Comprehensive Automated Forensic Remediation Tests for Threat Hunting.
Tests verify fixes for:
- DEF-HUNT-01: Full operator parity including not_contains, greater_than_or_equal, less_than_or_equal
- DEF-HUNT-02: payload_content search correctly mapped to PacketLog.raw_payload
- DEF-HUNT-03: Deterministic relative duration parsing (5m, 1h, 24h, 7d)
- DEF-HUNT-04: Canonical threat-score semantics (0.0 - 1.0) and auto-normalization
- DEF-HUNT-05: Proper error reporting and validation (422, 401, 403)
- Quick Templates execution
- IOC regex extraction, deduplication, and database watchlist persistence
- Real assignees endpoint (/api/v1/cases/assignees)
- Security, parameterization, and RBAC enforcement
"""

import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from main import app
from database.models import Base, PacketLog, User, IOC, InvestigationCase, CaseEvidence, SearchHistory
from database.database import get_db
from services.hunting_service import HuntingService
from middleware.auth import create_access_token, hash_password

from sqlalchemy.pool import StaticPool

# Deterministic test database with StaticPool so all threads/sessions share the same in-memory DB
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

FIXED_REF_TIME = datetime(2026, 10, 3, 12, 0, 0)


@pytest.fixture(scope="module", autouse=True)
def seed_test_data():
    """Seed test dataset for deterministic threat hunting testing."""
    db = TestingSessionLocal()
    db.query(PacketLog).delete()
    db.query(User).delete()
    db.query(IOC).delete()
    db.query(InvestigationCase).delete()

    # Create users
    admin_user = User(
        username="hunt_admin",
        email="admin@phantomnet.local",
        hashed_password=hash_password("AdminPass123!"),
        role="Admin",
        status="active",
    )
    analyst_user = User(
        username="hunt_analyst",
        email="analyst@phantomnet.local",
        hashed_password=hash_password("AnalystPass123!"),
        role="Analyst",
        status="active",
    )
    viewer_user = User(
        username="hunt_viewer",
        email="viewer@phantomnet.local",
        hashed_password=hash_password("ViewerPass123!"),
        role="Viewer",
        status="active",
    )
    db.add_all([admin_user, analyst_user, viewer_user])
    db.commit()

    # Seed events with known timestamps and payloads
    # Event 1: Recent Critical SQL Injection with payload
    log1 = PacketLog(
        timestamp=FIXED_REF_TIME - timedelta(minutes=10),
        src_ip="192.168.1.105",
        dst_ip="10.0.0.50",
        src_port=54321,
        dst_port=8080,
        protocol="TCP",
        length=256,
        attack_type="SQL Injection",
        threat_score=0.92,
        threat_level="CRITICAL",
        is_malicious=True,
        raw_payload="GET /search?q=1 UNION SELECT username, password FROM users --",
    )

    # Event 2: SSH Brute force within 6 hours
    log2 = PacketLog(
        timestamp=FIXED_REF_TIME - timedelta(hours=2),
        src_ip="198.51.100.44",
        dst_ip="10.0.0.50",
        src_port=44123,
        dst_port=2222,
        protocol="SSH",
        length=128,
        attack_type="Brute Force",
        threat_score=0.75,
        threat_level="HIGH",
        is_malicious=True,
        raw_payload="SSH-2.0-libssh_0.9.5 root login failure",
    )

    # Event 3: High threat within 18 hours
    log3 = PacketLog(
        timestamp=FIXED_REF_TIME - timedelta(hours=18),
        src_ip="203.0.113.12",
        dst_ip="10.0.0.50",
        src_port=51234,
        dst_port=8080,
        protocol="TCP",
        length=312,
        attack_type="Command Injection",
        threat_score=0.68,
        threat_level="HIGH",
        is_malicious=True,
        raw_payload="POST /api/exec cmd=;cat /etc/passwd",
    )

    # Event 4: Medium threat 3 days ago (outside 24h, inside 7d)
    log4 = PacketLog(
        timestamp=FIXED_REF_TIME - timedelta(days=3),
        src_ip="198.51.100.89",
        dst_ip="10.0.0.50",
        src_port=33444,
        dst_port=2121,
        protocol="FTP",
        length=64,
        attack_type="Port Scan",
        threat_score=0.45,
        threat_level="MEDIUM",
        is_malicious=False,
        raw_payload=None,
    )

    # Event 5: Low benign traffic 10 days ago (outside 7d)
    log5 = PacketLog(
        timestamp=FIXED_REF_TIME - timedelta(days=10),
        src_ip="10.0.1.20",
        dst_ip="10.0.0.50",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        length=60,
        attack_type="BENIGN",
        threat_score=0.10,
        threat_level="LOW",
        is_malicious=False,
        raw_payload="GET /healthcheck HTTP/1.1",
    )

    db.add_all([log1, log2, log3, log4, log5])
    db.commit()

    yield
    db.close()


@pytest.fixture
def admin_token():
    return create_access_token(data={"sub": "hunt_admin", "role": "Admin"})


@pytest.fixture
def analyst_token():
    return create_access_token(data={"sub": "hunt_analyst", "role": "Analyst"})


@pytest.fixture
def viewer_token():
    return create_access_token(data={"sub": "hunt_viewer", "role": "Viewer"})


# ============================================================
# PHASE 2: SEARCH OPERATOR CONTRACT (DEF-HUNT-01)
# ============================================================

def test_operator_not_contains(analyst_token):
    """DEF-HUNT-01: Verify not_contains operator functions end-to-end."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    payload = {
        "logic": "AND",
        "conditions": [
            {"field": "attack_type", "operator": "not_contains", "value": "SQL"}
        ]
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0
    for r in data["results"]:
        assert "SQL" not in (r["attack_type"] or "")


def test_operator_greater_than_or_equal(analyst_token):
    """DEF-HUNT-01: Verify greater_than_or_equal operator works properly."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    payload = {
        "logic": "AND",
        "conditions": [
            {"field": "threat_score", "operator": "greater_than_or_equal", "value": 0.68}
        ]
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3  # 0.92, 0.75, 0.68
    for r in data["results"]:
        assert r["threat_score"] >= 0.68


def test_operator_less_than_or_equal(analyst_token):
    """DEF-HUNT-01: Verify less_than_or_equal operator works properly."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    payload = {
        "logic": "AND",
        "conditions": [
            {"field": "threat_score", "operator": "less_than_or_equal", "value": 0.45}
        ]
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2  # 0.45, 0.10


def test_operator_between_and_in_list(analyst_token):
    """Verify between and in_list operators work properly."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    # Test in_list
    payload = {
        "logic": "AND",
        "conditions": [
            {"field": "protocol", "operator": "in_list", "value": ["SSH", "FTP"]}
        ]
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["total"] == 2

    # Test between
    payload_between = {
        "logic": "AND",
        "conditions": [
            {"field": "threat_score", "operator": "between", "value": [0.40, 0.80]}
        ]
    }
    res_between = client.post("/api/v1/hunting/search", json=payload_between, headers=headers)
    assert res_between.status_code == 200
    assert res_between.json()["total"] == 3  # 0.75, 0.68, 0.45


def test_invalid_operator_rejected_with_422(analyst_token):
    """DEF-HUNT-01: Invalid operators must be cleanly rejected with 422."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    payload = {
        "logic": "AND",
        "conditions": [
            {"field": "attack_type", "operator": "unsupported_xyz", "value": "test"}
        ]
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=headers)
    assert response.status_code == 422


# ============================================================
# PHASE 3: PAYLOAD CONTENT SEARCH (DEF-HUNT-02)
# ============================================================

def test_payload_content_contains(analyst_token):
    """DEF-HUNT-02: payload_content must search PacketLog.raw_payload."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    payload = {
        "logic": "AND",
        "conditions": [
            {"field": "payload_content", "operator": "contains", "value": "UNION SELECT"}
        ]
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    event = data["results"][0]
    assert "UNION SELECT" in event["payload_content"]
    assert event["src_ip"] == "192.168.1.105"


def test_payload_content_not_contains(analyst_token):
    """DEF-HUNT-02: payload_content not_contains must exclude matching payload."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    payload = {
        "logic": "AND",
        "conditions": [
            {"field": "payload_content", "operator": "not_contains", "value": "UNION SELECT"}
        ]
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    # Should exclude the 1 union select event
    for r in data["results"]:
        assert "UNION SELECT" not in r["payload_content"]


# ============================================================
# PHASE 4: RELATIVE TIME QUERIES (DEF-HUNT-03)
# ============================================================

def test_relative_time_parsing_unit():
    """DEF-HUNT-03: Deterministic unit tests for relative timestamp parser."""
    db = TestingSessionLocal()
    service = HuntingService(db)

    # 5m
    dt_5m = service._parse_timestamp_value("5m", reference_time=FIXED_REF_TIME)
    assert dt_5m == FIXED_REF_TIME - timedelta(minutes=5)

    # 1h
    dt_1h = service._parse_timestamp_value("1h", reference_time=FIXED_REF_TIME)
    assert dt_1h == FIXED_REF_TIME - timedelta(hours=1)

    # 24h & 24h_ago
    dt_24h = service._parse_timestamp_value("24h", reference_time=FIXED_REF_TIME)
    dt_24h_ago = service._parse_timestamp_value("24h_ago", reference_time=FIXED_REF_TIME)
    assert dt_24h == FIXED_REF_TIME - timedelta(hours=24)
    assert dt_24h_ago == FIXED_REF_TIME - timedelta(hours=24)

    # 7d
    dt_7d = service._parse_timestamp_value("7d", reference_time=FIXED_REF_TIME)
    assert dt_7d == FIXED_REF_TIME - timedelta(days=7)

    # Invalid relative duration must raise ValueError
    with pytest.raises(ValueError):
        service._parse_timestamp_value("invalid_duration", reference_time=FIXED_REF_TIME)

    db.close()


def test_relative_time_search_service():
    """DEF-HUNT-03: Service query with relative duration 24h filters correctly."""
    db = TestingSessionLocal()
    service = HuntingService(db)

    # Within last 24 hours relative to FIXED_REF_TIME:
    # Event 1 (10m ago), Event 2 (2h ago), Event 3 (18h ago) -> 3 events
    # Event 4 (3d ago) and Event 5 (10d ago) must be excluded
    query = {
        "logic": "AND",
        "conditions": [
            {"field": "timestamp", "operator": "greater_than_or_equal", "value": "24h"}
        ]
    }
    res = service.search_events(query, reference_time=FIXED_REF_TIME)
    assert res["total"] == 3
    for ev in res["results"]:
        dt = datetime.fromisoformat(ev["timestamp"])
        assert dt >= (FIXED_REF_TIME - timedelta(hours=24))

    # Within last 7 days: Events 1, 2, 3, 4 -> 4 events
    query_7d = {
        "logic": "AND",
        "conditions": [
            {"field": "timestamp", "operator": "greater_than_or_equal", "value": "7d"}
        ]
    }
    res_7d = service.search_events(query_7d, reference_time=FIXED_REF_TIME)
    assert res_7d["total"] == 4

    db.close()


# ============================================================
# PHASE 5: THREAT SCORE SCALE (DEF-HUNT-04)
# ============================================================

def test_threat_score_normalization():
    """DEF-HUNT-04: User entering 80 or 0.80 must produce identical canonical 0.80 filter."""
    db = TestingSessionLocal()
    service = HuntingService(db)

    # Query with canonical 0.80
    res_canonical = service.search_events({
        "logic": "AND",
        "conditions": [
            {"field": "threat_score", "operator": "greater_than_or_equal", "value": 0.80}
        ]
    })

    # Query with percentage/integer 80
    res_percent = service.search_events({
        "logic": "AND",
        "conditions": [
            {"field": "threat_score", "operator": "greater_than_or_equal", "value": 80}
        ]
    })

    # Both must match only Event 1 (score 0.92)
    assert res_canonical["total"] == 1
    assert res_percent["total"] == 1
    assert res_canonical["results"][0]["id"] == res_percent["results"][0]["id"]
    assert res_canonical["results"][0]["threat_score"] == 0.92

    db.close()


# ============================================================
# PHASE 6: QUICK TEMPLATES
# ============================================================

def test_quick_templates_execute_cleanly(analyst_token):
    """PHASE 6: Ensure all 5 Quick Templates execute without HTTP errors."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    templates = [
        # Template 1: All HIGH threats in 24h
        {
            "name": "All HIGH threats in 24h",
            "logic": "AND",
            "conditions": [
                {"field": "threat_level", "operator": "equals", "value": "HIGH"},
                {"field": "timestamp", "operator": "greater_than_or_equal", "value": "24h"}
            ]
        },
        # Template 2: SSH Traffic / Brute Force
        {
            "name": "SSH Traffic / Brute Force",
            "logic": "AND",
            "conditions": [
                {"field": "dst_port", "operator": "equals", "value": 2222},
                {"field": "threat_score", "operator": "greater_than_or_equal", "value": 0.40}
            ]
        },
        # Template 3: HTTP Honeypot Probing
        {
            "name": "HTTP Honeypot Probing",
            "logic": "AND",
            "conditions": [
                {"field": "dst_port", "operator": "equals", "value": 8080},
                {"field": "protocol", "operator": "equals", "value": "TCP"}
            ]
        },
        # Template 4: SQL Injection Attempts
        {
            "name": "SQL Injection Attempts",
            "logic": "AND",
            "conditions": [
                {"field": "attack_type", "operator": "contains", "value": "SQL"},
                {"field": "threat_score", "operator": "greater_than_or_equal", "value": 0.40}
            ]
        },
        # Template 5: Critical Threats (Any)
        {
            "name": "Critical Threats (Any)",
            "logic": "OR",
            "conditions": [
                {"field": "threat_level", "operator": "equals", "value": "CRITICAL"}
            ]
        }
    ]

    for tpl in templates:
        resp = client.post("/api/v1/hunting/search", json={"logic": tpl["logic"], "conditions": tpl["conditions"]}, headers=headers)
        assert resp.status_code == 200, f"Template '{tpl['name']}' failed with {resp.status_code}: {resp.text}"
        data = resp.json()
        assert "total" in data
        assert "results" in data


# ============================================================
# PHASE 9 & 10: IOC EXTRACTION & WATCHLIST PERSISTENCE
# ============================================================

def test_ioc_extraction_and_types():
    """PHASE 9: Verify regex extraction of multiple IOC categories without ML claims."""
    db = TestingSessionLocal()
    service = HuntingService(db)

    sample_log = (
        "Attacker from 45.33.32.156 and 2001:0db8:85a3:0000:0000:8a2e:0370:7334 visited "
        "https://malicious-c2.example.com/payload.exe, contact: admin@badactor.net. "
        "MD5: 5d41402abc4b2a76b9719d911017c592, "
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    iocs = service.extract_iocs(sample_log)
    extracted_types = {ioc["type"] for ioc in iocs}
    assert "IP" in extracted_types
    assert "IPv6" in extracted_types
    assert "Domain" in extracted_types
    assert "URL" in extracted_types
    assert "Email" in extracted_types
    assert "MD5" in extracted_types
    assert "SHA256" in extracted_types

    db.close()


def test_ioc_watchlist_persistence(analyst_token):
    """PHASE 10: Verify IOC watchlist toggles and persists to the database."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    target_ip = "198.51.100.99"

    # Toggle ON
    toggle_payload = {"type": "IP", "value": target_ip}
    res1 = client.post("/api/v1/hunting/watchlist/toggle", json=toggle_payload, headers=headers)
    assert res1.status_code == 200
    assert res1.json()["in_watchlist"] is True

    # Retrieve watchlist: must contain target_ip
    res2 = client.get("/api/v1/hunting/watchlist", headers=headers)
    assert res2.status_code == 200
    watchlist_items = res2.json()
    assert any(item["value"] == target_ip for item in watchlist_items)

    # Toggle OFF
    res3 = client.post("/api/v1/hunting/watchlist/toggle", json=toggle_payload, headers=headers)
    assert res3.status_code == 200
    assert res3.json()["in_watchlist"] is False

    # Retrieve watchlist again: target_ip must NOT be in active watchlist
    res4 = client.get("/api/v1/hunting/watchlist", headers=headers)
    assert res4.status_code == 200
    watchlist_items_after = res4.json()
    assert not any(item["value"] == target_ip for item in watchlist_items_after)


# ============================================================
# PHASE 11 & 12: REAL ASSIGNEES & CASE MANAGEMENT
# ============================================================

def test_assignees_endpoint_returns_real_users(analyst_token):
    """PHASE 11: GET /api/v1/cases/assignees must return real database users (no mock personas)."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    response = client.get("/api/v1/cases/assignees", headers=headers)
    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 2  # hunt_admin and hunt_analyst
    usernames = [u["username"] for u in users]
    assert "hunt_admin" in usernames
    assert "hunt_analyst" in usernames
    # Viewer must not be in assignees
    assert "hunt_viewer" not in usernames
    # Mock personas must NOT be present
    assert "M. Reddy" not in usernames
    assert "S. Kumar" not in usernames


def test_case_lifecycle_and_evidence(analyst_token):
    """PHASE 12: Verify case creation, real assignee, evidence attachment, and update."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # Create Case
    case_payload = {
        "title": "TH-SQLi-Investigation",
        "description": "SQL injection detected targeting honeypot node.",
        "priority": "Critical",
        "assigned_to": "hunt_analyst"
    }
    c_res = client.post("/api/v1/cases/", json=case_payload, headers=headers)
    assert c_res.status_code == 200
    case_data = c_res.json()
    case_id = case_data["id"]
    assert case_data["assigned_to"] == "hunt_analyst"
    assert case_data["priority"] == "Critical"

    # Attach Evidence
    ev_payload = {
        "event_id": 1,
        "event_type": "packet_log",
        "notes": "Primary SQL injection payload evidence"
    }
    ev_res = client.post(f"/api/v1/cases/{case_id}/evidence", json=ev_payload, headers=headers)
    assert ev_res.status_code == 200
    assert ev_res.json()["status"] == "success"

    # Update Status
    up_res = client.put(f"/api/v1/cases/{case_id}", json={"status": "In Progress"}, headers=headers)
    assert up_res.status_code == 200
    assert up_res.json()["status"] == "In Progress"


# ============================================================
# PHASE 14: SECURITY & RBAC
# ============================================================

def test_unauthenticated_requests_rejected():
    """PHASE 14: Unauthenticated access to hunting and case endpoints returns 401."""
    # Hunting search
    r1 = client.post("/api/v1/hunting/search", json={"logic": "AND", "conditions": []})
    assert r1.status_code == 401

    # Case assignees
    r2 = client.get("/api/v1/cases/assignees")
    assert r2.status_code == 401


def test_viewer_role_restrictions(viewer_token):
    """PHASE 14: Viewer role is forbidden from Analyst/Admin hunting endpoints."""
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # Viewer cannot search hunting
    r1 = client.post("/api/v1/hunting/search", json={"logic": "AND", "conditions": []}, headers=headers)
    assert r1.status_code == 403

    # Viewer cannot create cases
    r2 = client.post("/api/v1/cases/", json={"title": "Test", "description": "Test"}, headers=headers)
    assert r2.status_code == 403


def test_sql_injection_attempt_in_search_field(analyst_token):
    """PHASE 14: SQL injection payload in search query must be safely parameterized."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    sqli_payload = {
        "logic": "AND",
        "conditions": [
            {"field": "src_ip", "operator": "equals", "value": "192.168.1.1' OR '1'='1"}
        ]
    }
    response = client.post("/api/v1/hunting/search", json=sqli_payload, headers=headers)
    assert response.status_code == 200
    # Must safely match 0 records because no IP equals literally that string
    assert response.json()["total"] == 0


# ============================================================
# PHASE 15: REGRESSION TESTS FOR FORENSIC REMEDIATIONS (DEF-FOR-02 & DEF-FOR-04)
# ============================================================

def test_null_payload_not_contains_semantic_behavior(analyst_token):
    """DEF-FOR-02: not_contains on nullable columns must include NULL records and exclude matches."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # A. contains on NULL does NOT match: only 1 log has 'UNION SELECT' (log1)
    res_contains = client.post("/api/v1/hunting/search", json={
        "logic": "AND",
        "conditions": [{"field": "payload_content", "operator": "contains", "value": "UNION SELECT"}]
    }, headers=headers)
    assert res_contains.status_code == 200
    data_contains = res_contains.json()
    assert data_contains["total"] == 1
    assert data_contains["results"][0]["src_ip"] == "192.168.1.105"

    # B, C, D: not_contains must match NULL payloads (log4) + non-matching payloads (log2, log3, log5)
    # Total seeded logs = 5. Log 1 matches 'UNION SELECT', so 4 logs must be returned!
    res_not_contains = client.post("/api/v1/hunting/search", json={
        "logic": "AND",
        "conditions": [{"field": "payload_content", "operator": "not_contains", "value": "UNION SELECT"}]
    }, headers=headers)
    assert res_not_contains.status_code == 200
    data_not_contains = res_not_contains.json()
    assert data_not_contains["total"] == 4

    matched_ips = {r["src_ip"] for r in data_not_contains["results"]}
    # Log 1 (192.168.1.105) MUST BE EXCLUDED
    assert "192.168.1.105" not in matched_ips
    # Log 4 (198.51.100.89, raw_payload=NULL) MUST BE INCLUDED
    assert "198.51.100.89" in matched_ips
    # Log 2, Log 3, Log 5 MUST BE INCLUDED
    assert "198.51.100.44" in matched_ips
    assert "203.0.113.12" in matched_ips
    assert "10.0.1.20" in matched_ips


def test_unknown_search_field_rejected_with_422(analyst_token):
    """DEF-FOR-04: Unrecognized fields, typos, or dropped conditions must return HTTP 422."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # 1. Typo in field name
    r_typo = client.post("/api/v1/hunting/search", json={
        "logic": "AND",
        "conditions": [{"field": "threat_lvel", "operator": "equals", "value": "HIGH"}]
    }, headers=headers)
    assert r_typo.status_code == 422
    assert "threat_lvel" in str(r_typo.json())

    # 2. Completely unknown field
    r_unknown = client.post("/api/v1/hunting/search", json={
        "logic": "AND",
        "conditions": [{"field": "attacker_mac_address", "operator": "equals", "value": "aa:bb:cc"}]
    }, headers=headers)
    assert r_unknown.status_code == 422
    assert "attacker_mac_address" in str(r_unknown.json())

    # 3. Multiple conditions where one is invalid -> entire request rejected
    r_multi = client.post("/api/v1/hunting/search", json={
        "logic": "AND",
        "conditions": [
            {"field": "src_ip", "operator": "equals", "value": "192.168.1.1"},
            {"field": "unsupported_extra_field", "operator": "equals", "value": "foo"}
        ]
    }, headers=headers)
    assert r_multi.status_code == 422

    # 4. Valid fields remain accepted
    r_valid = client.post("/api/v1/hunting/search", json={
        "logic": "AND",
        "conditions": [
            {"field": "src_ip", "operator": "equals", "value": "10.0.1.20"},
            {"field": "protocol", "operator": "equals", "value": "TCP"}
        ]
    }, headers=headers)
    assert r_valid.status_code == 200
    assert r_valid.json()["total"] == 1


def test_cookie_auth_csrf_validation_and_header_requirement(analyst_token):
    """
    Browser Cookie Auth & CSRF Protection Regression Test.
    When a user is authenticated via session cookie:
    1. Requests lacking X-CSRF-Token or X-Requested-With are blocked with 403 CSRF validation failed.
    2. Requests with X-Requested-With: XMLHttpRequest (standard for AJAX/Axios) succeed with 200 OK.
    """
    client.cookies.set("phantomnet_access_token", analyst_token)

    try:
        # A. Without custom CSRF header -> rejected with 403
        r_no_csrf = client.post("/api/v1/hunting/search", json={
            "logic": "AND",
            "conditions": []
        })
        assert r_no_csrf.status_code == 403
        assert "CSRF validation failed" in r_no_csrf.json()["detail"]

        # B. With X-Requested-With: XMLHttpRequest -> accepted with 200
        r_with_csrf = client.post(
            "/api/v1/hunting/search",
            json={"logic": "AND", "conditions": []},
            headers={"X-Requested-With": "XMLHttpRequest"}
        )
        assert r_with_csrf.status_code == 200
        assert "total" in r_with_csrf.json()
    finally:
        client.cookies.clear()


def test_authentication_rbac_csrf_full_matrix(admin_token, analyst_token, viewer_token):
    """
    SECTION 16 AUTHENTICATION / RBAC / CSRF FULL MATRIX:
    A. No authentication: POST /api/v1/hunting/search -> EXPECT 401
    B. Viewer + valid CSRF: POST /api/v1/hunting/search -> EXPECT 403 RBAC
    C. Analyst + valid CSRF: POST /api/v1/hunting/search -> EXPECT 200
    D. Admin + valid CSRF: POST /api/v1/hunting/search -> EXPECT 200
    E. Admin cookie authentication WITHOUT CSRF header -> EXPECT 403 CSRF
    F. Admin cookie authentication WITH required CSRF header -> EXPECT 200
    """
    search_payload = {"logic": "AND", "conditions": []}

    # A. No authentication -> 401
    r_no_auth = client.post("/api/v1/hunting/search", json=search_payload)
    assert r_no_auth.status_code == 401
    assert "Not authenticated" in r_no_auth.json().get("detail", "")

    # B. Viewer + valid CSRF -> 403 RBAC (Requires role: Admin, Analyst)
    client.cookies.set("phantomnet_access_token", viewer_token)
    try:
        r_viewer = client.post(
            "/api/v1/hunting/search",
            json=search_payload,
            headers={"X-Requested-With": "XMLHttpRequest"}
        )
        assert r_viewer.status_code == 403
        detail = r_viewer.json().get("detail", "")
        assert "Requires role" in detail
        assert "CSRF" not in detail
    finally:
        client.cookies.clear()

    # C. Analyst + valid CSRF -> 200
    client.cookies.set("phantomnet_access_token", analyst_token)
    try:
        r_analyst = client.post(
            "/api/v1/hunting/search",
            json=search_payload,
            headers={"X-Requested-With": "XMLHttpRequest"}
        )
        assert r_analyst.status_code == 200
        assert "total" in r_analyst.json()
    finally:
        client.cookies.clear()

    # D. Admin + valid CSRF -> 200
    client.cookies.set("phantomnet_access_token", admin_token)
    try:
        r_admin = client.post(
            "/api/v1/hunting/search",
            json=search_payload,
            headers={"X-Requested-With": "XMLHttpRequest"}
        )
        assert r_admin.status_code == 200
        assert "total" in r_admin.json()
    finally:
        client.cookies.clear()

    # E. Admin cookie authentication WITHOUT CSRF header -> 403 CSRF
    client.cookies.set("phantomnet_access_token", admin_token)
    try:
        r_admin_no_csrf = client.post("/api/v1/hunting/search", json=search_payload)
        assert r_admin_no_csrf.status_code == 403
        detail = r_admin_no_csrf.json().get("detail", "")
        assert "CSRF validation failed: Missing custom request header" in detail
    finally:
        client.cookies.clear()

    # F. Admin cookie authentication WITH required CSRF header -> 200
    client.cookies.set("phantomnet_access_token", admin_token)
    try:
        r_admin_with_csrf = client.post(
            "/api/v1/hunting/search",
            json=search_payload,
            headers={"X-Requested-With": "XMLHttpRequest"}
        )
        assert r_admin_with_csrf.status_code == 200
        assert "total" in r_admin_with_csrf.json()
    finally:
        client.cookies.clear()



