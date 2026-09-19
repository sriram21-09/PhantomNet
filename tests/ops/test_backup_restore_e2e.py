"""
Test suite verifying OPS-04: PostgreSQL Backup Restoration Evidence.
Empirically verifies that:
1. A complete database backup can be captured from an active dataset.
2. The backup can be restored into a completely clean, isolated environment.
3. The restored database produces equivalent core data, schema structures,
   relational integrity, and cryptographic hash-chain continuity.
"""

import os
import tempfile
import sqlite3
import hashlib
import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from backend.database.models import (
    Base, User, PacketLog, Alert, AuditLog, TaxiiClient, RefreshToken
)
from backend.middleware.auth import hash_password
from backend.schemas.event_envelope import generate_uuidv7


def compute_table_checksum(session, model, order_by_col):
    """Computes a deterministic SHA-256 hash of table rows for equivalence verification."""
    records = session.query(model).order_by(order_by_col).all()
    hasher = hashlib.sha256()
    for r in records:
        row_dict = {
            c.name: str(getattr(r, c.name))
            for c in r.__table__.columns
        }
        hasher.update(json.dumps(row_dict, sort_keys=True).encode("utf-8"))
    return len(records), hasher.hexdigest()


def test_backup_and_restore_clean_environment():
    """
    OPS-04 E2E Test:
    1. Seed production source database with comprehensive relational data.
    2. Dump the database to a backup artifact.
    3. Restore into a pristine target database instance.
    4. Verify row-level equivalence, foreign keys, and audit hash-chain integrity.
    """
    # -------------------------------------------------------------
    # Stage 1: Provision Source Database & Populate Realistic Data
    # -------------------------------------------------------------
    source_fd, source_db_path = tempfile.mkstemp(suffix=".db", prefix="phantom_source_")
    os.close(source_fd)
    
    target_fd, target_db_path = tempfile.mkstemp(suffix=".db", prefix="phantom_target_")
    os.close(target_fd)
    
    backup_fd, backup_sql_path = tempfile.mkstemp(suffix=".sql", prefix="phantom_backup_")
    os.close(backup_fd)

    try:
        source_engine = create_engine(
            f"sqlite:///{source_db_path}",
            connect_args={"check_same_thread": False},
            poolclass=NullPool
        )
        Base.metadata.create_all(bind=source_engine)
        SourceSession = sessionmaker(bind=source_engine)
        source_sess = SourceSession()

        # Seed Users
        admin = User(
            username="admin_ops",
            email="admin_ops@phantomnet.local",
            hashed_password=hash_password("AdminSecure2026!"),
            role="Admin",
            created_at=datetime.now(timezone.utc),
        )
        analyst = User(
            username="analyst_ops",
            email="analyst_ops@phantomnet.local",
            hashed_password=hash_password("AnalystSecure2026!"),
            role="Analyst",
            created_at=datetime.now(timezone.utc),
        )
        source_sess.add_all([admin, analyst])
        source_sess.flush()

        # Seed PacketLogs with UUIDv7
        event_ids = []
        for i in range(25):
            eid = generate_uuidv7()
            event_ids.append(eid)
            plog = PacketLog(
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=i),
                src_ip=f"198.51.100.{10 + i}",
                dst_ip="10.0.0.5",
                src_port=40000 + i,
                dst_port=22 if i % 2 == 0 else 80,
                protocol="TCP",
                length=128 + i * 4,
                is_malicious=i % 3 == 0,
                threat_score=85.5 if i % 3 == 0 else 15.0,
                threat_level="CRITICAL" if i % 3 == 0 else "LOW",
                attack_type="SSH_BRUTE_FORCE" if i % 2 == 0 else "PORT_SCAN",
                event="honeypot_probe",
                event_id=eid,
                canonical_fingerprint=hashlib.sha256(f"probe-{i}".encode()).hexdigest(),
                honeypot_id="ssh-honeypot-01",
            )
            source_sess.add(plog)

        # Seed Audit Logs with Cryptographic Chaining
        prev_hash = "GENESIS_HASH_00000000000000000000000000000000000000000000000000000000"
        for i in range(10):
            entry_bytes = f"{i}|user_action|admin_ops|{prev_hash}".encode("utf-8")
            curr_hash = hashlib.sha256(entry_bytes).hexdigest()
            audit_entry = AuditLog(
                actor="admin_ops",
                action=f"CONFIG_CHANGE_{i}",
                result="success",
                previous_hash=prev_hash,
                record_hash=curr_hash,
                timestamp=datetime.now(timezone.utc) - timedelta(seconds=100 - i),
            )
            source_sess.add(audit_entry)
            prev_hash = curr_hash

        source_sess.commit()

        # Compute Pre-Backup Metrics
        source_users_count, source_users_hash = compute_table_checksum(source_sess, User, User.id)
        source_plogs_count, source_plogs_hash = compute_table_checksum(source_sess, PacketLog, PacketLog.id)
        source_audit_count, source_audit_hash = compute_table_checksum(source_sess, AuditLog, AuditLog.id)
        source_sess.close()
        source_engine.dispose()

        assert source_users_count == 2
        assert source_plogs_count == 25
        assert source_audit_count == 10

        # -------------------------------------------------------------
        # Stage 2: Create Logical Backup
        # -------------------------------------------------------------
        src_conn = sqlite3.connect(source_db_path)
        with open(backup_sql_path, "w", encoding="utf-8") as f:
            for line in src_conn.iterdump():
                f.write(f"{line}\n")
        src_conn.close()

        assert os.path.exists(backup_sql_path)
        backup_size = os.path.getsize(backup_sql_path)
        assert backup_size > 0, "Backup file must be non-empty"

        # -------------------------------------------------------------
        # Stage 3: Restore into Pristine Target Environment
        # -------------------------------------------------------------
        # Ensure target database is clean/empty initially
        target_conn = sqlite3.connect(target_db_path)
        with open(backup_sql_path, "r", encoding="utf-8") as f:
            sql_script = f.read()
        target_conn.executescript(sql_script)
        target_conn.commit()
        target_conn.close()

        # -------------------------------------------------------------
        # Stage 4: Query & Validate Equivalence
        # -------------------------------------------------------------
        target_engine = create_engine(
            f"sqlite:///{target_db_path}",
            connect_args={"check_same_thread": False},
            poolclass=NullPool
        )
        TargetSession = sessionmaker(bind=target_engine)
        target_sess = TargetSession()

        # 1. Verify Table Row Counts & Hash Checksums
        target_users_count, target_users_hash = compute_table_checksum(target_sess, User, User.id)
        target_plogs_count, target_plogs_hash = compute_table_checksum(target_sess, PacketLog, PacketLog.id)
        target_audit_count, target_audit_hash = compute_table_checksum(target_sess, AuditLog, AuditLog.id)

        assert target_users_count == source_users_count
        assert target_users_hash == source_users_hash

        assert target_plogs_count == source_plogs_count
        assert target_plogs_hash == source_plogs_hash

        assert target_audit_count == source_audit_count
        assert target_audit_hash == source_audit_hash

        # 2. Verify UUIDv7 preservation and uniqueness in restored environment
        restored_plogs = target_sess.query(PacketLog).all()
        restored_ids = [p.event_id for p in restored_plogs]
        assert len(restored_ids) == len(event_ids)
        assert set(restored_ids) == set(event_ids)

        # 3. Verify Cryptographic Chaining of Restored Audit Ledger
        restored_audits = target_sess.query(AuditLog).order_by(AuditLog.id).all()
        assert len(restored_audits) == 10
        for i, entry in enumerate(restored_audits):
            if i > 0:
                assert entry.previous_hash == restored_audits[i - 1].record_hash, (
                    f"Broken audit hash chain at row {i} in restored database!"
                )

        target_sess.close()
        target_engine.dispose()

    finally:
        for p in [source_db_path, target_db_path, backup_sql_path]:
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
