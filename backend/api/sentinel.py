"""
backend/api/sentinel.py
-------------------------
PhantomNet Sentinel Layer — REST API Endpoints

Provides 5 endpoints for the Sentinel Dashboard:

  GET  /api/sentinel/playbooks          — List all playbooks (paginated)
  GET  /api/sentinel/playbooks/{id}     — Get single playbook by ID
  GET  /api/sentinel/stats              — Playbook pipeline statistics
  GET  /api/sentinel/mitre/mapping      — All 12 ATT&CK technique mappings
  POST /api/sentinel/generate           — Trigger manual playbook generation

Router prefix: /api/sentinel
Tags: ['Sentinel']

Week 14, Day 2 — Integration & API
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from database.database import get_db
from sentinel.models import SentinelPlaybook
from sentinel.mitre_mapper import get_all_techniques
from sentinel.sentinel_service import SentinelService

logger = logging.getLogger("api.sentinel")

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/api/sentinel", tags=["Sentinel"])


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class PlaybookSummary(BaseModel):
    """Lightweight playbook representation for list endpoints."""
    id: int
    playbook_id: str
    src_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    attack_type: Optional[str] = None
    threat_score: Optional[float] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    playbook_name: Optional[str] = None
    status: str = "pending"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True


class PlaybookDetail(PlaybookSummary):
    """Full playbook representation including content and rules."""
    mitre_url: Optional[str] = None
    snort_rule: Optional[str] = None
    sigma_rule: Optional[str] = None
    playbook_content: Optional[str] = None
    template_name: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None

    class Config:
        from_attributes = True


class GenerateRequest(BaseModel):
    """Request body for POST /generate."""
    source_ips: List[str] = Field(..., min_length=1, description="Attacker source IP addresses")
    target_ports: List[int] = Field(..., min_length=1, description="Target destination ports")
    protocols: List[str] = Field(default=["TCP"], description="Network protocols")
    event_count: int = Field(default=0, ge=0, description="Number of events in campaign")
    campaign_id: Optional[str] = Field(default=None, description="Campaign identifier")
    time_range: Optional[Dict[str, str]] = Field(default=None, description="Time range with start/end ISO-8601 strings")


class GenerateResponse(BaseModel):
    """Response body for POST /generate."""
    status: str
    playbook_id: str
    db_record_id: int
    service_type: str
    attack_type: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    threat_score: float
    message: str


# ---------------------------------------------------------------------------
# Helper: serialise a SentinelPlaybook ORM row to dict
# ---------------------------------------------------------------------------

def _serialize_playbook_summary(row: SentinelPlaybook) -> dict:
    """Convert a SentinelPlaybook ORM object to a summary dict."""
    return {
        "id": row.id,
        "playbook_id": row.playbook_id,
        "src_ip": row.src_ip,
        "dst_port": row.dst_port,
        "protocol": row.protocol,
        "attack_type": row.attack_type,
        "threat_score": row.threat_score,
        "technique_id": row.technique_id,
        "technique_name": row.technique_name,
        "tactic": row.tactic,
        "playbook_name": row.playbook_name,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _serialize_playbook_detail(row: SentinelPlaybook) -> dict:
    """Convert a SentinelPlaybook ORM object to a full detail dict."""
    data = _serialize_playbook_summary(row)
    data.update({
        "mitre_url": row.mitre_url,
        "snort_rule": row.snort_rule,
        "sigma_rule": row.sigma_rule,
        "playbook_content": row.playbook_content,
        "template_name": row.template_name,
        "reviewed_by": row.reviewed_by,
        "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
    })
    return data


# ---------------------------------------------------------------------------
# 1. GET /api/sentinel/playbooks — List all playbooks with pagination
# ---------------------------------------------------------------------------

@router.get("/playbooks", response_model=Dict[str, Any])
def list_playbooks(
    limit: int = Query(default=20, ge=1, le=100, description="Max results per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    status: Optional[str] = Query(default=None, description="Filter by status: pending|approved|rejected|exported"),
    attack_type: Optional[str] = Query(default=None, description="Filter by attack type"),
    db: Session = Depends(get_db),
):
    """
    List all Sentinel playbooks with pagination and optional filtering.

    Query parameters:
      - **limit**: Maximum number of results (1–100, default 20)
      - **offset**: Pagination offset (default 0)
      - **status**: Filter by workflow status
      - **attack_type**: Filter by attack classification
    """
    try:
        query = db.query(SentinelPlaybook)

        if status is not None and status.strip():
            query = query.filter(SentinelPlaybook.status == status.strip().lower())
        if attack_type is not None and attack_type.strip():
            query = query.filter(SentinelPlaybook.attack_type == attack_type.strip())

        total = query.count()
        playbooks = (
            query
            .order_by(SentinelPlaybook.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        return {
            "status": "success",
            "total": total,
            "limit": limit,
            "offset": offset,
            "playbooks": [_serialize_playbook_summary(p) for p in playbooks],
        }
    except Exception as exc:
        logger.error("Failed to list playbooks: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to query playbooks: {str(exc)}")


# ---------------------------------------------------------------------------
# 2. GET /api/sentinel/playbooks/{id} — Get single playbook by ID
# ---------------------------------------------------------------------------

@router.get("/playbooks/{playbook_id}", response_model=Dict[str, Any])
def get_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
):
    """
    Get a single Sentinel playbook by its database ID.

    Returns the full playbook detail including content, Snort/Sigma rules,
    and MITRE ATT&CK mapping.
    """
    row = db.query(SentinelPlaybook).filter(SentinelPlaybook.id == playbook_id).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Playbook with id={playbook_id} not found")

    return {
        "status": "success",
        "playbook": _serialize_playbook_detail(row),
    }


# ---------------------------------------------------------------------------
# 3. GET /api/sentinel/stats — Playbook pipeline statistics
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
def get_sentinel_stats(
    db: Session = Depends(get_db),
):
    """
    Return Sentinel pipeline statistics.

    Includes total playbook count and breakdown by status
    (pending, approved, rejected, exported).
    """
    try:
        total = db.query(func.count(SentinelPlaybook.id)).scalar() or 0

        # Count by status
        status_counts = (
            db.query(SentinelPlaybook.status, func.count(SentinelPlaybook.id))
            .group_by(SentinelPlaybook.status)
            .all()
        )
        status_map = {status: count for status, count in status_counts}

        # Average threat score
        avg_score = db.query(func.avg(SentinelPlaybook.threat_score)).scalar()
        avg_score = round(float(avg_score), 2) if avg_score else 0.0

        # Latest playbook timestamp
        latest = (
            db.query(SentinelPlaybook.created_at)
            .order_by(SentinelPlaybook.created_at.desc())
            .first()
        )
        latest_at = latest[0].isoformat() if latest and latest[0] else None

        # Top attack types
        top_attacks = (
            db.query(SentinelPlaybook.attack_type, func.count(SentinelPlaybook.id))
            .group_by(SentinelPlaybook.attack_type)
            .order_by(func.count(SentinelPlaybook.id).desc())
            .limit(5)
            .all()
        )

        return {
            "status": "success",
            "total_playbooks": total,
            "pending": status_map.get("pending", 0),
            "approved": status_map.get("approved", 0),
            "rejected": status_map.get("rejected", 0),
            "exported": status_map.get("exported", 0),
            "avg_threat_score": avg_score,
            "latest_playbook_at": latest_at,
            "top_attack_types": [
                {"attack_type": at, "count": c} for at, c in top_attacks
            ],
        }
    except Exception as exc:
        logger.error("Failed to compute sentinel stats: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to compute stats: {str(exc)}")


# ---------------------------------------------------------------------------
# 4. GET /api/sentinel/mitre/mapping — All 12 ATT&CK technique mappings
# ---------------------------------------------------------------------------

@router.get("/mitre/mapping", response_model=Dict[str, Any])
def get_mitre_mappings():
    """
    Return all 12 MITRE ATT&CK technique mappings used by the Sentinel pipeline.

    Each mapping shows the signature name, technique ID, technique name,
    tactic, severity, and the official ATT&CK reference URL.
    """
    try:
        techniques = get_all_techniques()
        return {
            "status": "success",
            "total": len(techniques),
            "mappings": techniques,
        }
    except Exception as exc:
        logger.error("Failed to retrieve MITRE mappings: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve mappings: {str(exc)}")


# ---------------------------------------------------------------------------
# 5. POST /api/sentinel/generate — Trigger manual playbook generation
# ---------------------------------------------------------------------------

@router.post("/generate", response_model=Dict[str, Any])
def generate_playbook(
    request: GenerateRequest,
    db: Session = Depends(get_db),
):
    """
    Trigger manual playbook generation for a campaign.

    Runs the full Sentinel pipeline:
      mapper → generator → rules → stix → DB save

    The request body must include at least `source_ips` and `target_ports`.
    """
    try:
        campaign_data = {
            "source_ips": request.source_ips,
            "target_ports": request.target_ports,
            "protocols": request.protocols,
            "event_count": request.event_count,
            "campaign_id": request.campaign_id or "MANUAL-GEN",
            "time_range": request.time_range,
        }

        svc = SentinelService(db)
        playbook = svc.generate_playbook(campaign_data)

        result = playbook.result_dict

        return {
            "status": "success",
            "playbook_id": result["playbook_id"],
            "db_record_id": result["db_record_id"],
            "service_type": result["service_type"],
            "attack_type": result["attack_type"],
            "technique_id": result["technique"]["id"],
            "technique_name": result["technique"]["name"],
            "threat_score": result["threat_score"],
            "matched_logs_count": result["matched_logs_count"],
            "detected_signatures": result["detected_signatures"],
            "message": f"Playbook {result['playbook_id']} generated successfully",
        }
    except Exception as exc:
        logger.error("Playbook generation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Playbook generation failed: {str(exc)}")
