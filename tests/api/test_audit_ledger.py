"""
tests/api/test_audit_ledger.py
------------------------------
Verifies Cryptographic Tamper-Resistant Audit Logging (SEC-08):
- Cryptographic hash chaining: Each record includes SHA-256 hash of previous record.
- Integrity verification: Recomputes hashes across the ledger.
- Tamper detection: Any modification to actor, action, timestamp, or payload breaks the chain.
"""
import pytest
from database.models import AuditLog
from services.audit_service import audit_log, verify_audit_chain


def test_audit_ledger_sequential_chaining(db_session):
    """Writing consecutive audit logs correctly links previous_hash to preceding record_hash."""
    # Identify preceding hash if any test ran prior in the test session
    prior_entry = db_session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    expected_start_hash = prior_entry.record_hash if prior_entry else "GENESIS_BLOCK"

    entry_1 = audit_log(
        actor="sec_ops_1",
        action="USER_LOGIN",
        target="dashboard",
        result="success",
        db=db_session,
    )
    assert entry_1.previous_hash == expected_start_hash
    assert entry_1.record_hash is not None

    entry_2 = audit_log(
        actor="sec_ops_1",
        action="BLOCK_IP",
        target="198.51.100.12",
        result="success",
        db=db_session,
    )
    assert entry_2.previous_hash == entry_1.record_hash

    entry_3 = audit_log(
        actor="admin",
        action="EXPORT_RULES",
        target="snort_rules",
        result="success",
        db=db_session,
    )
    assert entry_3.previous_hash == entry_2.record_hash

    # Validate intact chain
    is_valid, count, error = verify_audit_chain(db_session)
    assert is_valid is True
    assert count >= 3
    assert error is None


def test_audit_ledger_tamper_detection(db_session):
    """Modifying an existing audit log entry causes verify_audit_chain to detect tampering."""
    entry = audit_log(
        actor="malicious_actor",
        action="DATABASE_QUERY",
        target="users",
        result="denied",
        db=db_session,
    )
    
    # Tamper with the actor name directly in the database
    entry.actor = "innocent_user"
    db_session.commit()

    # Integrity verification must catch the tampered record
    is_valid, count, error = verify_audit_chain(db_session)
    assert is_valid is False
    assert error is not None
    assert "Tampered record" in error or "Broken chain" in error
