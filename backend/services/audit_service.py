"""
Audit Service for PhantomNet (Phase 1 & Phase 3 Governance).

Provides structured, tamper-evident audit logging with SHA-256 cryptographic hash chaining.
Every security-critical operation (blocking IPs, modifying policies, user management, TAXII access)
generates an immutable record linked to the preceding entry in the ledger.
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session
from database.database import SessionLocal
from database.models import AuditLog

logger = logging.getLogger("phantomnet.audit")


def audit_log(
    actor: str,
    action: str,
    result: str,
    target: Optional[str] = None,
    request_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    reason: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    db: Optional[Session] = None,
) -> AuditLog:
    """Record a structured, tamper-evident audit entry with cryptographic hash chaining.

    Parameters
    ----------
    actor : str
        The username, system agent, or API key identifier executing the action.
    action : str
        Action identifier (e.g. "BLOCK_IP", "UNBLOCK_IP", "UPDATE_POLICY", "USER_CREATE").
    result : str
        Outcome: "success", "failure", or "denied".
    target : Optional[str]
        The subject of the operation (e.g., target IP, username, playbook ID).
    request_id : Optional[str]
        Correlating HTTP request ID or trace ID.
    source_ip : Optional[str]
        Client IP address from which the request originated.
    reason : Optional[str]
        Analyst justification or automated trigger explanation.
    details : Optional[Dict[str, Any]]
        Arbitrary structured context (before/after states, parameters).
    db : Optional[Session]
        Existing database session. If None, a dedicated session will be opened and committed.
    """
    owns_session = False
    if db is None:
        db = SessionLocal()
        owns_session = True

    try:
        # Retrieve the latest record's hash to maintain the cryptographic chain
        last_log = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        prev_hash = last_log.record_hash if last_log and last_log.record_hash else "GENESIS_BLOCK"

        now = datetime.utcnow()
        details_str = json.dumps(details, sort_keys=True) if details else None

        # Hash computation covering all critical fields and the link to history
        hash_payload = (
            f"{actor}|{action}|{target or ''}|{result}|{request_id or ''}|"
            f"{source_ip or ''}|{prev_hash}|{now.isoformat()}|{details_str or ''}"
        )
        current_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        entry = AuditLog(
            actor=actor,
            action=action,
            target=target,
            result=result,
            request_id=request_id,
            source_ip=source_ip,
            reason=reason,
            details=details_str,
            previous_hash=prev_hash,
            record_hash=current_hash,
            timestamp=now,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)

        # Emit structured log for real-time SIEM / syslog shipping
        logger.info(
            "AUDIT_RECORD: actor=%s action=%s target=%s result=%s request_id=%s ip=%s hash=%s",
            actor,
            action,
            target,
            result,
            request_id,
            source_ip,
            current_hash[:16],
            extra={
                "audit": {
                    "id": entry.id,
                    "actor": actor,
                    "action": action,
                    "target": target,
                    "result": result,
                    "request_id": request_id,
                    "source_ip": source_ip,
                    "reason": reason,
                    "hash": current_hash,
                    "timestamp": now.isoformat(),
                }
            },
        )
        return entry
    finally:
        if owns_session:
            db.close()


def verify_audit_chain(db: Session) -> Tuple[bool, int, Optional[str]]:
    """Verify cryptographic integrity of the entire audit log table.

    Returns
    -------
    Tuple[bool, int, Optional[str]]
        (is_valid, records_verified, error_detail)
    """
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    if not logs:
        return True, 0, None

    expected_prev = "GENESIS_BLOCK"
    for idx, log in enumerate(logs):
        # 1. Verify previous_hash linkage
        if log.previous_hash != expected_prev:
            return (
                False,
                idx,
                f"Broken chain at ID {log.id}: expected previous_hash {expected_prev}, found {log.previous_hash}",
            )

        # 2. Recompute record hash
        hash_payload = (
            f"{log.actor}|{log.action}|{log.target or ''}|{log.result}|{log.request_id or ''}|"
            f"{log.source_ip or ''}|{log.previous_hash}|{log.timestamp.isoformat()}|{log.details or ''}"
        )
        recomputed = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
        if recomputed != log.record_hash:
            return (
                False,
                idx,
                f"Tampered record at ID {log.id}: computed hash {recomputed}, recorded hash {log.record_hash}",
            )

        expected_prev = log.record_hash

    return True, len(logs), None
