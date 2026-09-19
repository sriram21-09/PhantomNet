"""
backend/api/governance.py
-------------------------
Database Governance & Data Retention API Endpoints (GOV-01, GOV-02, GOV-03).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Security, status
from sqlalchemy.orm import Session
from typing import Any, Dict

from database.database import get_db
from database.models import User
from middleware.auth import require_role
from services.retention_service import retention_engine, RetentionConfig

router = APIRouter(prefix="/api/v1/governance", tags=["Governance"])


@router.get("/retention/policies")
def get_retention_policies(
    current_user: User = Depends(require_role("Viewer", "Analyst", "Admin")),
) -> Dict[str, Any]:
    """
    Returns current active data retention policies.
    """
    cfg = retention_engine.config
    return {
        "packet_logs_days": cfg.packet_logs_days,
        "events_days": cfg.events_days,
        "alerts_days": cfg.alerts_days,
        "traffic_stats_days": cfg.traffic_stats_days,
        "pcaps_days": cfg.pcaps_days,
        "audit_logs_days": cfg.audit_logs_days,
        "audit_log_immutable": cfg.audit_log_immutable,
        "batch_size": cfg.batch_size,
    }


@router.post("/retention/run")
def run_retention_cycle_endpoint(
    dry_run: bool = Query(default=True, description="When true, counts eligible rows without deletion"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("Admin")),
) -> Dict[str, Any]:
    """
    Executes a tiered retention cycle.
    Admin authorization required.
    """
    actor = getattr(current_user, "username", "admin_operator")
    results = retention_engine.run_retention_cycle(db=db, dry_run=dry_run, actor=actor)
    return results
