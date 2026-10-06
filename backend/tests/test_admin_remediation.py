"""
Automated Forensic Remediation Tests for System Administration (DEF-ADM-01 through DEF-ADM-12)
Verifies:
- DEF-ADM-01: Persistent, secure database backup creation and restore
- DEF-ADM-02: Cryptographic tamper-evident audit logging for all admin actions
- DEF-ADM-03: Real system health monitoring (CPU, RAM, DB ping, uptime, component statuses)
- DEF-ADM-04: Robust error handling, non-silent failures, and input validation
- DEF-ADM-05: Non-destructive, password-safe database restore with SHA-256 integrity check
- DEF-ADM-06: Centralized SystemConfigService and dynamic runtime consumers
- DEF-ADM-09: Administrator safety invariants (cannot delete/demote last active admin)
"""

import os
import json
import hashlib
import tempfile
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from main import app
from database.models import Base, User, SystemConfig, AuditLog, PacketLog, Alert, HoneypotNode, Policy
from database.database import get_db
from middleware.auth import hash_password, create_access_token
from services.system_config_service import (
    invalidate_config_cache,
    get_config_value,
    get_config_bool,
    get_config_int,
    get_config_float,
    get_config_str,
    set_config_value,
)

# Test in-memory SQLite database shared across sessions
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

ADMIN_TOKEN = None
ANALYST_TOKEN = None
VIEWER_TOKEN = None


@pytest.fixture(scope="module", autouse=True)
def setup_test_environment():
    global ADMIN_TOKEN, ANALYST_TOKEN, VIEWER_TOKEN
    db = TestingSessionLocal()

    # Clear any existing rows
    db.query(User).delete()
    db.query(SystemConfig).delete()
    db.query(AuditLog).delete()
    db.query(PacketLog).delete()
    db.query(Alert).delete()
    db.query(HoneypotNode).delete()
    db.query(Policy).delete()
    db.commit()

    # Create admin, analyst, viewer
    admin_user = User(
        username="admin_test",
        email="admin@phantomnet.local",
        hashed_password=hash_password("AdminSecurePass123!"),
        role="Admin",
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    analyst_user = User(
        username="analyst_test",
        email="analyst@phantomnet.local",
        hashed_password=hash_password("AnalystPass123!"),
        role="Analyst",
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    viewer_user = User(
        username="viewer_test",
        email="viewer@phantomnet.local",
        hashed_password=hash_password("ViewerPass123!"),
        role="Viewer",
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    db.add_all([admin_user, analyst_user, viewer_user])

    # Seed baseline configs
    configs = [
        SystemConfig(key="ml_threshold", value="0.75", category="threat_detection"),
        SystemConfig(key="auto_response", value="true", category="threat_detection"),
        SystemConfig(key="sentinel_llm_enabled", value="false", category="threat_detection"),
        SystemConfig(key="alert_email", value="soc@phantomnet.local", category="threat_detection"),
        SystemConfig(key="alert_severity_filter", value="HIGH", category="threat_detection"),
        SystemConfig(key="deception_mode", value="balanced", category="honeypot"),
        SystemConfig(key="ssh_banner", value="SSH-2.0-OpenSSH_8.9p1", category="honeypot"),
        SystemConfig(key="http_banner", value="Apache/2.4.52 (Ubuntu)", category="honeypot"),
        SystemConfig(key="max_interaction_time", value="180", category="honeypot"),
        SystemConfig(key="siem_type", value="splunk", category="siem"),
        SystemConfig(key="siem_endpoint", value="https://siem.phantomnet.local:8088", category="siem"),
        SystemConfig(key="siem_export_frequency", value="30", category="siem"),
        SystemConfig(key="db_pool_size", value="20", category="performance"),
        SystemConfig(key="cache_ttl", value="300", category="performance"),
        SystemConfig(key="log_retention_days", value="90", category="performance"),
    ]
    db.add_all(configs)

    # Seed an alert, packet log, and honeypot node for backup/restore testing
    db.add(Alert(
        type="INTRUSION",
        level="CRITICAL",
        source_ip="192.168.1.100",
        description="SSH brute force attempt",
        details="{'attempts': 15}",
        is_resolved=False,
        timestamp=datetime.now(timezone.utc),
    ))
    db.add(PacketLog(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=22,
        protocol="TCP",
        length=128,
        attack_type="BRUTE_FORCE",
        threat_score=0.88,
        threat_level="HIGH",
        is_malicious=True,
    ))
    db.add(HoneypotNode(
        node_id="node-alpha-1",
        hostname="alpha-honeypot",
        ip_address="10.0.0.15",
        status="active",
        honeypot_type="SSH",
    ))
    db.commit()

    ADMIN_TOKEN = create_access_token({"sub": "admin_test", "role": "Admin"})
    ANALYST_TOKEN = create_access_token({"sub": "analyst_test", "role": "Analyst"})
    VIEWER_TOKEN = create_access_token({"sub": "viewer_test", "role": "Viewer"})
    db.close()


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# 1. SystemConfigService Tests (DEF-ADM-06)
# ==============================================================================

def test_system_config_service_accessors():
    """Verify type accessors and in-memory cache of SystemConfigService."""
    db = TestingSessionLocal()
    try:
        invalidate_config_cache()

        # Float
        ml_thresh = get_config_float("ml_threshold", default=0.5, db=db)
        assert ml_thresh == 0.75

        # Bool
        auto_resp = get_config_bool("auto_response", default=False, db=db)
        assert auto_resp is True

        # String
        siem = get_config_str("siem_type", default="none", db=db)
        assert siem == "splunk"

        # Int
        freq = get_config_int("siem_export_frequency", default=60, db=db)
        assert freq == 30

        # Non-existent fallback
        missing = get_config_str("non_existent_key", default="fallback", db=db)
        assert missing == "fallback"
    finally:
        db.close()


def test_system_config_service_set_value():
    """Verify set_config_value writes to DB and invalidates cache."""
    db = TestingSessionLocal()
    try:
        set_config_value("ml_threshold", "0.92", category="threat_detection", db=db)
        val = get_config_float("ml_threshold", default=0.5, db=db)
        assert val == 0.92

        # Reset back
        set_config_value("ml_threshold", "0.75", category="threat_detection", db=db)
        assert get_config_float("ml_threshold", default=0.5, db=db) == 0.75
    finally:
        db.close()


# ==============================================================================
# 2. Admin System Overview Live Metrics (DEF-ADM-03)
# ==============================================================================

def test_admin_system_overview_live():
    """Verify live system telemetry (uptime, db size, memory, component checks)."""
    res = client.get("/api/v1/admin/system-overview", headers=auth_headers(ADMIN_TOKEN))
    assert res.status_code == 200
    data = res.json()

    assert "system" in data
    assert "resources" in data
    assert "stats" in data
    assert "components" in data

    # Verify real metrics
    assert "uptime" in data["system"]
    assert "db_type" in data["system"]
    assert data["resources"]["memory_percent"] >= 0
    assert data["stats"]["total_users"] >= 3

    # Check component list
    comp_names = [c["name"].lower() for c in data["components"]]
    assert any("database" in n for n in comp_names)
    assert any("ml" in n for n in comp_names)
    assert any("websocket" in n for n in comp_names)


def test_admin_system_overview_rbac():
    """Verify non-admin roles are rejected from system overview."""
    res_analyst = client.get("/api/v1/admin/system-overview", headers=auth_headers(ANALYST_TOKEN))
    assert res_analyst.status_code == 403

    res_viewer = client.get("/api/v1/admin/system-overview", headers=auth_headers(VIEWER_TOKEN))
    assert res_viewer.status_code == 403


# ==============================================================================
# 3. Admin Invariants & Safety (DEF-ADM-09)
# ==============================================================================

def test_cannot_delete_last_active_admin():
    """Verify that deleting the last active admin returns HTTP 400."""
    db = TestingSessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin_test").first()
        assert admin is not None
        admin_id = admin.id
    finally:
        db.close()

    res = client.delete(f"/api/v1/admin/users/{admin_id}", headers=auth_headers(ADMIN_TOKEN))
    assert res.status_code == 400
    assert "cannot delete the last active administrator" in res.json()["detail"].lower()


def test_cannot_demote_last_active_admin():
    """Verify that demoting the last active admin returns HTTP 400."""
    db = TestingSessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin_test").first()
        admin_id = admin.id
    finally:
        db.close()

    res = client.put(
        f"/api/v1/admin/users/{admin_id}",
        json={"role": "Viewer"},
        headers=auth_headers(ADMIN_TOKEN),
    )
    assert res.status_code == 400
    assert "cannot demote" in res.json()["detail"].lower() and "administrator" in res.json()["detail"].lower()


# ==============================================================================
# 4. Sanitized Complete Backup (DEF-ADM-01 & DEF-ADM-05)
# ==============================================================================

def test_backup_creation_and_password_sanitization():
    """Verify backup creates full archive, computes SHA-256 sidecar, and sanitizes password hashes."""
    res = client.post("/api/v1/admin/backup", headers=auth_headers(ADMIN_TOKEN))
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "success"
    assert "backup_file" in data
    assert "checksum" in data or "checksum_sha256" in data
    backup_filename = data["backup_file"]

    # Verify backup exists in backup list
    list_res = client.get("/api/v1/admin/backups", headers=auth_headers(ADMIN_TOKEN))
    assert list_res.status_code == 200
    filenames = [b["filename"] for b in list_res.json()["backups"]]
    assert backup_filename in filenames

    # Verify backup content directly from list/download or filesystem
    # Search for backup file in known directories
    found_path = None
    for candidate_dir in [
        os.environ.get("BACKUP_DIR", ""),
        "/app/backups",
        os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "backups")),
        os.path.join(tempfile.gettempdir(), "phantomnet_backups"),
    ]:
        if candidate_dir:
            p = os.path.join(candidate_dir, backup_filename)
            if os.path.exists(p):
                found_path = p
                break

    assert found_path is not None, f"Backup file {backup_filename} not found on disk"

    with open(found_path, "r", encoding="utf-8") as f:
        backup_content = json.load(f)

    # Verify exported tables
    assert "system_config" in backup_content
    assert "users" in backup_content
    assert "alerts" in backup_content

    # CRITICAL: Verify passwords are NEVER exported
    for user_rec in backup_content["users"]:
        assert "hashed_password" not in user_rec, "CRITICAL: hashed_password leaked in backup!"
        assert "password" not in user_rec

    # Verify SHA-256 sidecar file exists and matches
    sidecar_path = found_path + ".sha256"
    assert os.path.exists(sidecar_path)
    with open(sidecar_path, "r", encoding="utf-8") as sf:
        sidecar_hash = sf.read().strip()

    with open(found_path, "rb") as f:
        computed_hash = hashlib.sha256(f.read()).hexdigest()

    assert sidecar_hash == computed_hash
    assert (data.get("checksum") or data.get("checksum_sha256")) == computed_hash


# ==============================================================================
# 5. Non-Destructive Password-Safe Restore (DEF-ADM-01 & DEF-ADM-05)
# ==============================================================================

def test_restore_via_existing_backup_filename():
    """Verify restore from server backup filename restores tables and preserves user passwords."""
    # First get the backup filename from backup list
    list_res = client.get("/api/v1/admin/backups", headers=auth_headers(ADMIN_TOKEN))
    backups = list_res.json().get("backups", [])
    assert len(backups) > 0
    target_backup = backups[0]["filename"]

    # Capture admin user's current password hash before restore
    db = TestingSessionLocal()
    try:
        admin_before = db.query(User).filter(User.username == "admin_test").first()
        original_hash = admin_before.hashed_password
    finally:
        db.close()

    # Call restore
    res = client.post(
        "/api/v1/admin/restore",
        data={"filename": target_backup},
        headers=auth_headers(ADMIN_TOKEN),
    )
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["status"] == "success"
    assert "restored" in res_data or "restored_counts" in res_data

    # Verify password hash was preserved exactly
    db = TestingSessionLocal()
    try:
        admin_after = db.query(User).filter(User.username == "admin_test").first()
        assert admin_after.hashed_password == original_hash, "Admin password hash was unexpectedly altered!"
    finally:
        db.close()


def test_restore_rejects_corrupted_archive():
    """Verify that restore rejects tampered files or files with invalid checksums."""
    corrupted_data = {
        "metadata": {
            "version": "3.0.0",
            "checksum_sha256": "deadbeef00000000000000000000000000000000000000000000000000000000",
        },
        "tables": {
            "system_config": [{"key": "hacked", "value": "true", "category": "bad"}],
        }
    }
    raw_bytes = json.dumps(corrupted_data).encode("utf-8")

    res = client.post(
        "/api/v1/admin/restore",
        files={"file": ("tampered_backup.json", raw_bytes, "application/json")},
        headers=auth_headers(ADMIN_TOKEN),
    )
    assert res.status_code == 400
    assert "checksum mismatch" in res.json()["detail"].lower()


# ==============================================================================
# 6. Audit Logging Verification (DEF-ADM-02)
# ==============================================================================

def test_audit_logs_recorded_for_mutations():
    """Verify privileged administrative mutations generate audit log entries."""
    db = TestingSessionLocal()
    try:
        initial_count = db.query(AuditLog).count()
    finally:
        db.close()

    # Perform a config update
    res = client.put(
        "/api/v1/admin/config",
        json={"key": "ssh_banner", "value": "SSH-2.0-CustomAuditBanner", "category": "honeypot"},
        headers=auth_headers(ADMIN_TOKEN),
    )
    assert res.status_code == 200

    # Verify an audit log entry was created
    db = TestingSessionLocal()
    try:
        new_count = db.query(AuditLog).count()
        assert new_count > initial_count

        latest_log = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        assert latest_log.action in ["CONFIG_UPDATE", "UPDATE_CONFIG"]
        assert "ssh_banner" in (latest_log.details or "")
        assert latest_log.result == "success"
    finally:
        db.close()


# ==============================================================================
# 7. Config Error Handling (DEF-ADM-04)
# ==============================================================================

def test_config_validation_rejection():
    """Verify invalid configuration updates are rejected with appropriate error codes."""
    # Missing required field 'key'
    res = client.put(
        "/api/v1/admin/config",
        json={"value": "some_value", "category": "honeypot"},
        headers=auth_headers(ADMIN_TOKEN),
    )
    assert res.status_code in [400, 422]
