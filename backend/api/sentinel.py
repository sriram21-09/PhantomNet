"""
backend/api/sentinel.py
-------------------------
PhantomNet Sentinel Layer — REST API Endpoints

Provides 10 endpoints for the Sentinel Dashboard:

  GET   /api/sentinel/playbooks              — List all playbooks (paginated)
  GET   /api/sentinel/playbooks/{id}         — Get single playbook by ID
  GET   /api/sentinel/stats                  — Playbook pipeline statistics
  GET   /api/sentinel/mitre/mapping          — All 12 ATT&CK technique mappings
  POST  /api/sentinel/generate               — Trigger manual playbook generation
  PATCH /api/sentinel/playbooks/{id}/approve — Approve a playbook
  PATCH /api/sentinel/playbooks/{id}/reject  — Reject a playbook
  POST  /api/sentinel/playbooks/{id}/export  — Export playbook as file download
  GET   /api/sentinel/rules/snort            — List all Snort rules
  GET   /api/sentinel/rules/sigma            — List all Sigma rules

Router prefix: /api/sentinel
Tags: ['Sentinel']

Week 14, Day 2 + Day 3 — Integration & API
"""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
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


class ReviewRequest(BaseModel):
    """Request body for PATCH /approve and /reject endpoints."""
    reviewed_by: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Username of the analyst performing the review",
    )

    @field_validator("reviewed_by")
    @classmethod
    def validate_reviewed_by(cls, v: str) -> str:
        """Strip whitespace and reject empty reviewed_by values."""
        v = v.strip()
        if not v:
            raise ValueError("reviewed_by must not be empty or whitespace")
        return v


# ---------------------------------------------------------------------------
# Helper: serialise a SentinelPlaybook ORM row to dict
# ---------------------------------------------------------------------------

def _serialize_playbook_summary(row: SentinelPlaybook) -> Dict[str, Any]:
    """Convert a SentinelPlaybook ORM object to a summary dict.

    Includes core identity, threat context, MITRE mapping, and lifecycle
    fields.  Datetime columns are serialised to ISO-8601 strings.

    Args:
        row: SentinelPlaybook ORM instance.

    Returns:
        Dictionary with 14 summary fields.
    """
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


def _serialize_playbook_detail(row: SentinelPlaybook) -> Dict[str, Any]:
    """Convert a SentinelPlaybook ORM object to a full detail dict.

    Extends :func:`_serialize_playbook_summary` with rules, playbook
    content, and review lifecycle fields.

    Args:
        row: SentinelPlaybook ORM instance.

    Returns:
        Dictionary with all 21 serialised fields.
    """
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
    page: int = Query(default=1, ge=1, description="Page number (1-indexed, default 1)"),
    per_page: int = Query(default=20, ge=1, le=100, description="Results per page (1–100, default 20)"),
    status: Optional[str] = Query(default=None, description="Filter by status: pending|approved|rejected|exported"),
    attack_type: Optional[str] = Query(default=None, description="Filter by attack type"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    List all Sentinel playbooks with page-based pagination and optional filtering.

    Args:
        page: Page number, 1-indexed (default 1).
        per_page: Results per page, 1-100 (default 20).
        status: Filter by workflow status (pending|approved|rejected|exported).
        attack_type: Filter by attack classification label.
        db: Injected database session.

    Returns:
        Dict with keys: status, total, page, per_page, playbooks[].

    Raises:
        HTTPException 500: On unexpected database errors.
    """
    try:
        query = db.query(SentinelPlaybook)

        if status is not None and status.strip():
            query = query.filter(SentinelPlaybook.status == status.strip().lower())
        if attack_type is not None and attack_type.strip():
            query = query.filter(SentinelPlaybook.attack_type == attack_type.strip())

        total = query.count()

        # Calculate offset from page/per_page
        offset = (page - 1) * per_page

        playbooks = (
            query
            .order_by(SentinelPlaybook.created_at.desc())
            .offset(offset)
            .limit(per_page)
            .all()
        )

        return {
            "status": "success",
            "total": total,
            "page": page,
            "per_page": per_page,
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
) -> Dict[str, Any]:
    """
    Get a single Sentinel playbook by its database ID.

    Returns the full playbook detail including content, Snort/Sigma rules,
    and MITRE ATT&CK mapping.

    Args:
        playbook_id: Integer primary key of the playbook.
        db: Injected database session.

    Returns:
        JSON response with full playbook detail.

    Raises:
        HTTPException 404: If no playbook exists with the given ID.
        HTTPException 500: On unexpected database errors.
    """
    try:
        row = db.query(SentinelPlaybook).filter(SentinelPlaybook.id == playbook_id).first()
        if not row:
            raise HTTPException(status_code=404, detail=f"Playbook with id={playbook_id} not found")

        return {
            "status": "success",
            "playbook": _serialize_playbook_detail(row),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to retrieve playbook id=%d: %s", playbook_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve playbook: {str(exc)}")


# ---------------------------------------------------------------------------
# 3. GET /api/sentinel/stats — Playbook pipeline statistics
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
def get_sentinel_stats(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Return Sentinel pipeline statistics.

    Includes total playbook count and breakdown by status
    (pending, approved, rejected, exported).

    Args:
        db: Injected database session.

    Returns:
        Dict with keys: status, total_playbooks, pending, approved,
        rejected, exported, avg_threat_score, latest_playbook_at,
        top_attack_types.

    Raises:
        HTTPException 500: On unexpected database errors.
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
def get_mitre_mappings() -> Dict[str, Any]:
    """
    Return all 12 MITRE ATT&CK technique mappings used by the Sentinel pipeline.

    Each mapping shows the signature name, technique ID, technique name,
    tactic, severity, and the official ATT&CK reference URL.

    Returns:
        Dict with keys: status, total, mappings[].

    Raises:
        HTTPException 500: On unexpected errors.
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
) -> Dict[str, Any]:
    """
    Trigger manual playbook generation for a campaign.

    Runs the full Sentinel pipeline:
      mapper -> generator -> rules -> stix -> DB save

    Args:
        request: GenerateRequest with source_ips, target_ports, etc.
        db: Injected database session.

    Returns:
        Dict with keys: status, playbook_id, db_record_id, service_type,
        attack_type, technique_id, technique_name, threat_score, message.

    Raises:
        HTTPException 500: On pipeline failure.
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


# ---------------------------------------------------------------------------
# 6. PATCH /api/sentinel/playbooks/{id}/approve — Approve a playbook
# ---------------------------------------------------------------------------

@router.patch("/playbooks/{playbook_id}/approve", response_model=Dict[str, Any])
def approve_playbook(
    playbook_id: int = Path(..., ge=1, description="Database ID of the playbook to approve"),
    body: ReviewRequest = ...,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Approve a Sentinel playbook.

    Updates **three** fields atomically:
      - ``status`` -> ``"approved"``
      - ``reviewed_by`` -> analyst username from request body
      - ``reviewed_at`` -> current UTC timestamp

    Args:
        playbook_id: Database ID of the playbook to approve.
        body: ReviewRequest with reviewed_by username.
        db: Injected database session.

    Returns:
        Dict with keys: status, message, playbook (full detail).

    Raises:
        HTTPException 404: If playbook not found.
        HTTPException 409: If playbook status is not pending/rejected.
        HTTPException 500: On database commit failure.
    """
    row = db.query(SentinelPlaybook).filter(SentinelPlaybook.id == playbook_id).first()
    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"Playbook with id={playbook_id} not found",
        )

    if row.status not in ("pending", "rejected"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot approve playbook with status='{row.status}'. "
                   f"Only 'pending' or 'rejected' playbooks can be approved.",
        )

    try:
        row.status = "approved"
        row.reviewed_by = body.reviewed_by
        row.reviewed_at = datetime.now(tz=timezone.utc)
        db.commit()
        db.refresh(row)
        logger.info(
            "Playbook id=%d approved by %s", playbook_id, body.reviewed_by
        )
    except Exception as exc:
        db.rollback()
        logger.error("Failed to approve playbook id=%d: %s", playbook_id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to approve playbook: {str(exc)}",
        )

    return {
        "status": "success",
        "message": f"Playbook {row.playbook_id} approved by {body.reviewed_by}",
        "playbook": _serialize_playbook_detail(row),
    }


# ---------------------------------------------------------------------------
# 7. PATCH /api/sentinel/playbooks/{id}/reject — Reject a playbook
# ---------------------------------------------------------------------------

@router.patch("/playbooks/{playbook_id}/reject", response_model=Dict[str, Any])
def reject_playbook(
    playbook_id: int = Path(..., ge=1, description="Database ID of the playbook to reject"),
    body: ReviewRequest = ...,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Reject a Sentinel playbook.

    Updates **three** fields atomically:
      - ``status`` -> ``"rejected"``
      - ``reviewed_by`` -> analyst username from request body
      - ``reviewed_at`` -> current UTC timestamp

    Args:
        playbook_id: Database ID of the playbook to reject.
        body: ReviewRequest with reviewed_by username.
        db: Injected database session.

    Returns:
        Dict with keys: status, message, playbook (full detail).

    Raises:
        HTTPException 404: If playbook not found.
        HTTPException 409: If playbook status is not pending/approved.
        HTTPException 500: On database commit failure.
    """
    row = db.query(SentinelPlaybook).filter(SentinelPlaybook.id == playbook_id).first()
    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"Playbook with id={playbook_id} not found",
        )

    if row.status not in ("pending", "approved"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot reject playbook with status='{row.status}'. "
                   f"Only 'pending' or 'approved' playbooks can be rejected.",
        )

    try:
        row.status = "rejected"
        row.reviewed_by = body.reviewed_by
        row.reviewed_at = datetime.now(tz=timezone.utc)
        db.commit()
        db.refresh(row)
        logger.info(
            "Playbook id=%d rejected by %s", playbook_id, body.reviewed_by
        )
    except Exception as exc:
        db.rollback()
        logger.error("Failed to reject playbook id=%d: %s", playbook_id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reject playbook: {str(exc)}",
        )

    return {
        "status": "success",
        "message": f"Playbook {row.playbook_id} rejected by {body.reviewed_by}",
        "playbook": _serialize_playbook_detail(row),
    }


# ---------------------------------------------------------------------------
# 8. POST /api/sentinel/playbooks/{id}/export — Export playbook as file
# ---------------------------------------------------------------------------

_VALID_EXPORT_FORMATS = {"markdown", "json", "stix"}


@router.post("/playbooks/{playbook_id}/export", response_class=StreamingResponse)
def export_playbook(
    playbook_id: int = Path(..., ge=1, description="Database ID of the playbook to export"),
    format: str = Query(
        default="markdown",
        description="Export format: markdown | json | stix",
    ),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """
    Export a Sentinel playbook as a downloadable file.

    Supported formats via ``?format=`` query parameter:
      - **markdown** -- Playbook content as ``.md`` file (default)
      - **json** -- Full playbook record as ``.json`` file
      - **stix** -- STIX 2.1 bundle as ``.json`` file (generated on-the-fly)

    Args:
        playbook_id: Database ID of the playbook to export.
        format: Export format string (markdown|json|stix).
        db: Injected database session.

    Returns:
        StreamingResponse with the file download.

    Raises:
        HTTPException 400: If export format is invalid.
        HTTPException 404: If playbook not found.
    """
    fmt = format.strip().lower()
    if fmt not in _VALID_EXPORT_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid export format '{format}'. "
                   f"Supported formats: {', '.join(sorted(_VALID_EXPORT_FORMATS))}",
        )

    row = db.query(SentinelPlaybook).filter(SentinelPlaybook.id == playbook_id).first()
    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"Playbook with id={playbook_id} not found",
        )

    safe_name = (row.playbook_id or f"playbook-{playbook_id}").replace(" ", "_")

    # ── Build export content based on format ──────────────────────────────
    if fmt == "markdown":
        content = row.playbook_content or f"# {row.playbook_name}\n\nNo content available."
        media_type = "text/markdown; charset=utf-8"
        filename = f"{safe_name}.md"

    elif fmt == "json":
        export_data = _serialize_playbook_detail(row)
        export_data["exported_at"] = datetime.now(tz=timezone.utc).isoformat()
        content = json.dumps(export_data, indent=2, default=str)
        media_type = "application/json; charset=utf-8"
        filename = f"{safe_name}.json"

    elif fmt == "stix":
        # Build a STIX 2.1 bundle on-the-fly from the playbook's technique data
        try:
            from sentinel.stix_enhanced import build_stix_bundle, bundle_to_json

            technique = {
                "technique_id": row.technique_id or "T1046",
                "technique_name": row.technique_name or "Network Service Discovery",
                "tactic": row.tactic or "Discovery",
                "url": row.mitre_url or "",
                "severity": "HIGH" if (row.threat_score or 0) >= 70 else "MEDIUM",
            }
            iocs = [{"type": "ip", "value": row.src_ip}] if row.src_ip else []
            tlp = "amber" if (row.threat_score or 0) >= 70 else "green"
            bundle = build_stix_bundle(
                technique=technique,
                iocs=iocs,
                src_ip=row.src_ip,
                threat_score=row.threat_score or 0.0,
                tlp_level=tlp,
            )
            content = bundle_to_json(bundle, pretty=True)
        except Exception as exc:
            logger.warning("STIX bundle generation failed for export: %s", exc)
            # Fallback: export the JSON representation
            export_data = _serialize_playbook_detail(row)
            export_data["exported_at"] = datetime.now(tz=timezone.utc).isoformat()
            export_data["stix_error"] = str(exc)
            content = json.dumps(export_data, indent=2, default=str)

        media_type = "application/json; charset=utf-8"
        filename = f"{safe_name}_stix.json"

    # ── Update status to exported ─────────────────────────────────────────
    try:
        row.status = "exported"
        row.updated_at = datetime.now(tz=timezone.utc)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("Failed to update export status for id=%d: %s", playbook_id, exc)

    # ── Return file download ──────────────────────────────────────────────
    buffer = io.BytesIO(content.encode("utf-8"))
    buffer.seek(0)

    return StreamingResponse(
        content=buffer,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Playbook-Id": row.playbook_id or "",
            "X-Export-Format": fmt,
        },
    )


# ---------------------------------------------------------------------------
# 9. GET /api/sentinel/rules/snort — List all Snort rules
# ---------------------------------------------------------------------------

@router.get("/rules/snort", response_model=Dict[str, Any])
def list_snort_rules(
    limit: int = Query(default=50, ge=1, le=200, description="Max results per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    attack_type: Optional[str] = Query(default=None, description="Filter by attack type"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    List all Snort IDS rules generated by the Sentinel pipeline.

    Returns playbooks that have a non-null ``snort_rule`` field, with
    pagination and optional attack_type filtering.

    Args:
        limit: Max results per page (1-200, default 50).
        offset: Pagination offset (default 0).
        attack_type: Filter by attack classification label.
        db: Injected database session.

    Returns:
        Dict with keys: status, total, limit, offset, rules[].

    Raises:
        HTTPException 500: On unexpected database errors.
    """
    try:
        query = db.query(SentinelPlaybook).filter(
            SentinelPlaybook.snort_rule.isnot(None),
            SentinelPlaybook.snort_rule != "",
        )

        if attack_type is not None and attack_type.strip():
            query = query.filter(SentinelPlaybook.attack_type == attack_type.strip())

        total = query.count()
        rows = (
            query
            .order_by(SentinelPlaybook.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        rules = []
        for row in rows:
            rules.append({
                "id": row.id,
                "playbook_id": row.playbook_id,
                "attack_type": row.attack_type,
                "technique_id": row.technique_id,
                "technique_name": row.technique_name,
                "src_ip": row.src_ip,
                "dst_port": row.dst_port,
                "threat_score": row.threat_score,
                "snort_rule": row.snort_rule,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            })

        return {
            "status": "success",
            "total": total,
            "limit": limit,
            "offset": offset,
            "rules": rules,
        }
    except Exception as exc:
        logger.error("Failed to list Snort rules: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to query Snort rules: {str(exc)}")


# ---------------------------------------------------------------------------
# 10. GET /api/sentinel/rules/sigma — List all Sigma rules
# ---------------------------------------------------------------------------

@router.get("/rules/sigma", response_model=Dict[str, Any])
def list_sigma_rules(
    limit: int = Query(default=50, ge=1, le=200, description="Max results per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    attack_type: Optional[str] = Query(default=None, description="Filter by attack type"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    List all Sigma detection rules generated by the Sentinel pipeline.

    Returns playbooks that have a non-null ``sigma_rule`` field, with
    pagination and optional attack_type filtering.

    Args:
        limit: Max results per page (1-200, default 50).
        offset: Pagination offset (default 0).
        attack_type: Filter by attack classification label.
        db: Injected database session.

    Returns:
        Dict with keys: status, total, limit, offset, rules[].

    Raises:
        HTTPException 500: On unexpected database errors.
    """
    try:
        query = db.query(SentinelPlaybook).filter(
            SentinelPlaybook.sigma_rule.isnot(None),
            SentinelPlaybook.sigma_rule != "",
        )

        if attack_type is not None and attack_type.strip():
            query = query.filter(SentinelPlaybook.attack_type == attack_type.strip())

        total = query.count()
        rows = (
            query
            .order_by(SentinelPlaybook.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        rules = []
        for row in rows:
            rules.append({
                "id": row.id,
                "playbook_id": row.playbook_id,
                "attack_type": row.attack_type,
                "technique_id": row.technique_id,
                "technique_name": row.technique_name,
                "src_ip": row.src_ip,
                "dst_port": row.dst_port,
                "threat_score": row.threat_score,
                "sigma_rule": row.sigma_rule,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            })

        return {
            "status": "success",
            "total": total,
            "limit": limit,
            "offset": offset,
            "rules": rules,
        }
    except Exception as exc:
        logger.error("Failed to list Sigma rules: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to query Sigma rules: {str(exc)}")
