"""
PhantomNet PCAP API Router
===========================
Endpoints for downloading PCAPs, viewing analysis results,
and retrieving capture statistics.
"""

import os
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import Event, PcapCapture, PacketLog, User
from middleware.auth import require_role
from services.pcap_analyzer import pcap_analyzer

logger = logging.getLogger("api.pcap")
router = APIRouter(
    prefix="/api/v1",
    tags=["PCAP Analysis"],
    dependencies=[Depends(require_role("Admin", "Analyst"))],
)

PCAP_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "data", "pcaps")
)


def _is_safe_pcap_path(path: str) -> bool:
    """Verify that a path is strictly inside the authorized PCAP directory."""
    abs_path = os.path.abspath(path)
    return abs_path.startswith(PCAP_DIR + os.sep) or abs_path == PCAP_DIR


def _resolve_pcap_path(target_id: int, db: Session) -> Optional[str]:
    """
    Safely resolve the absolute filesystem path for a capture/event ID.
    Enforces _is_safe_pcap_path at every stage.
    """
    # 1. Check Event.pcap_path
    event = db.query(Event).filter(Event.id == target_id).first()
    if event and event.pcap_path:
        if not _is_safe_pcap_path(event.pcap_path):
            logger.warning("Path traversal attempt detected on event %d: %s", target_id, event.pcap_path)
            raise HTTPException(status_code=403, detail="Invalid PCAP file path")
        if os.path.exists(event.pcap_path):
            return event.pcap_path

    # 2. Check PcapCapture record (id, event_id, or packet_log_id)
    cap_rec = db.query(PcapCapture).filter(
        (PcapCapture.id == target_id)
        | (PcapCapture.event_id == target_id)
        | (PcapCapture.packet_log_id == target_id)
    ).first()
    if cap_rec and cap_rec.file_path:
        if not _is_safe_pcap_path(cap_rec.file_path):
            logger.warning("Path traversal attempt detected on capture %d: %s", target_id, cap_rec.file_path)
            raise HTTPException(status_code=403, detail="Invalid PCAP file path")
        if os.path.exists(cap_rec.file_path):
            return cap_rec.file_path

    # 3. Direct filename match in PCAP_DIR
    candidate = os.path.join(PCAP_DIR, f"{target_id}.pcap")
    if not _is_safe_pcap_path(candidate):
        raise HTTPException(status_code=403, detail="Invalid PCAP file path")
    if os.path.exists(candidate):
        return candidate

    return None


# ------------------------------------------------------------------
# GET /api/v1/pcap/captures — List available captures
# ------------------------------------------------------------------
@router.get("/pcap/captures")
def list_captures(
    limit: int = Query(50, ge=1, le=500, description="Max captures to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    search: Optional[str] = Query(None, description="Search by ID or filename"),
    status: Optional[str] = Query(None, description="Filter by capture status"),
    sort: str = Query("desc", pattern="^(asc|desc)$", description="Sort order"),
    order_by: str = Query("created_at", pattern="^(created_at|id|file_size|packet_count)$", description="Sort column"),
    db: Session = Depends(get_db),
):
    """
    Return a paginated list of available PCAP captures.
    Metadata includes capture ID, filename, size, timestamp, packet count, status, and linked IDs.
    Supports search, filtering, and sorting.
    """
    pcap_analyzer.sync_database_captures(db)
    query = db.query(PcapCapture)

    if status:
        query = query.filter(PcapCapture.analysis_status == status)

    if search:
        search_clean = search.strip()
        if search_clean.isdigit():
            query = query.filter(
                (PcapCapture.id == int(search_clean))
                | (PcapCapture.event_id == int(search_clean))
                | (PcapCapture.packet_log_id == int(search_clean))
                | (PcapCapture.file_path.ilike(f"%{search_clean}%"))
            )
        else:
            query = query.filter(PcapCapture.file_path.ilike(f"%{search_clean}%"))

    total = query.count()

    col = getattr(PcapCapture, order_by, PcapCapture.created_at)
    if sort == "asc":
        query = query.order_by(col.asc(), PcapCapture.id.asc())
    else:
        query = query.order_by(col.desc(), PcapCapture.id.desc())

    records = query.offset(offset).limit(limit).all()

    captures = [
        {
            "id": rec.id,
            "filename": os.path.basename(rec.file_path) if rec.file_path else f"{rec.id}.pcap",
            "size_bytes": rec.file_size or 0,
            "size_mb": round((rec.file_size or 0) / 1_000_000, 2),
            "packet_count": rec.packet_count or 0,
            "status": rec.analysis_status or "available",
            "timestamp": rec.created_at.isoformat() if rec.created_at else None,
            "event_id": rec.event_id,
            "packet_log_id": rec.packet_log_id,
        }
        for rec in records
    ]

    return {
        "status": "success",
        "total": total,
        "limit": limit,
        "offset": offset,
        "captures": captures,
    }


# ------------------------------------------------------------------
# GET /api/v1/pcap/{capture_id}/download — Download PCAP by capture ID
# ------------------------------------------------------------------
@router.get("/pcap/{capture_id}/download")
@router.get("/pcap/download/{capture_id}")
def download_capture(
    capture_id: int = Path(..., ge=1, description="PCAP Capture database ID"),
    db: Session = Depends(get_db),
):
    """Download a PCAP file by its capture ID."""
    pcap_path = _resolve_pcap_path(capture_id, db)
    if not pcap_path:
        raise HTTPException(status_code=404, detail=f"PCAP capture {capture_id} not found")

    return FileResponse(
        path=pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"phantomnet_capture_{capture_id}.pcap",
    )


# ------------------------------------------------------------------
# GET /api/v1/events/{id}/pcap — Download PCAP file (backward compat)
# ------------------------------------------------------------------
@router.get("/events/{event_id}/pcap")
def download_pcap(
    event_id: int = Path(..., ge=1, description="Event or PCAP database ID"),
    db: Session = Depends(get_db),
):
    """Download the PCAP file associated with an event or capture ID."""
    pcap_path = _resolve_pcap_path(event_id, db)
    if not pcap_path:
        raise HTTPException(status_code=404, detail="PCAP file not found for this event")

    return FileResponse(
        path=pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"phantomnet_event_{event_id}.pcap",
    )


# ------------------------------------------------------------------
# GET /api/v1/pcap/analysis/{id} — Get analysis results
# ------------------------------------------------------------------
@router.get("/pcap/analysis/{event_id}")
def get_pcap_analysis(
    event_id: int = Path(..., ge=1, description="Event or PCAP database ID"),
    db: Session = Depends(get_db),
):
    """Return the deep packet analysis for a given PCAP capture."""
    pcap_path = _resolve_pcap_path(event_id, db)
    if not pcap_path or not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail=f"PCAP capture {event_id} not found on disk")

    try:
        analysis = pcap_analyzer.analyze_pcap(pcap_path)
        if "error" in analysis:
            raise HTTPException(status_code=500, detail=analysis["error"])
        report = pcap_analyzer.generate_report(analysis)
        report["event_id"] = event_id
        report["capture_id"] = event_id
        report["status"] = "analyzed"

        # Update cached metadata in DB if available
        cap = db.query(PcapCapture).filter(PcapCapture.id == event_id).first()
        if cap and not cap.packet_count and analysis.get("total_packets"):
            cap.packet_count = analysis.get("total_packets")
            cap.analysis_status = "complete"
            db.commit()

        return {
            "status": "success",
            "event_id": event_id,
            "capture_id": event_id,
            "report": report,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error analyzing PCAP for event %d: %s", event_id, e)
        raise HTTPException(status_code=500, detail="Failed to analyze PCAP file.")


# ------------------------------------------------------------------
# GET /api/v1/pcap/stats — Capture system statistics
# ------------------------------------------------------------------
@router.get("/pcap/stats")
def pcap_stats(db: Session = Depends(get_db)):
    """Return overall PCAP capture statistics."""
    try:
        pcap_analyzer.sync_database_captures(db)
        stats = pcap_analyzer.get_stats()
        return {
            "status": "success",
            **stats,
        }
    except Exception as e:
        logger.error("Error retrieving PCAP stats: %s", e)
        raise HTTPException(status_code=500, detail="Failed to retrieve PCAP statistics.")


# ------------------------------------------------------------------
# POST /api/v1/pcap/capture/{event_id} — Trigger manual capture
# ------------------------------------------------------------------
@router.post("/pcap/capture/{event_id}")
def trigger_capture(
    event_id: int = Path(..., ge=1, description="Event database ID"),
    duration: int = Query(60, ge=1, le=3600, description="Capture duration in seconds"),
    db: Session = Depends(get_db),
):
    """Manually trigger a packet capture for an event."""
    event = db.query(Event).filter(Event.id == event_id).first()
    pkt_log = db.query(PacketLog).filter(PacketLog.id == event_id).first() if not event else None
    if not event and not pkt_log:
        raise HTTPException(status_code=404, detail="Event or PacketLog not found")

    try:
        result = pcap_analyzer.start_capture(event_id=event_id, duration=duration)
        return {
            "status": "success",
            "capture": result,
        }
    except Exception as e:
        logger.error("Error triggering capture for event %d: %s", event_id, e)
        raise HTTPException(status_code=500, detail="Failed to start packet capture.")


# ------------------------------------------------------------------
# GET /api/v1/pcap/capture/{event_id}/status — Check capture status
# ------------------------------------------------------------------
@router.get("/pcap/capture/{event_id}/status")
def capture_status(
    event_id: int = Path(..., ge=1, description="Event database ID"),
):
    """Check the status of an active or completed capture."""
    try:
        status = pcap_analyzer.get_capture_status(event_id)
        return {
            "status": "success",
            "capture": status,
        }
    except Exception as e:
        logger.error("Error getting capture status for event %d: %s", event_id, e)
        raise HTTPException(status_code=500, detail="Failed to retrieve capture status.")


# ------------------------------------------------------------------
# POST /api/v1/pcap/cleanup — Manual retention cleanup
# ------------------------------------------------------------------
@router.post("/pcap/cleanup")
def run_cleanup(
    retention_days: int = Query(30, ge=1, le=365, description="Retention window in days"),
):
    """Manually trigger PCAP retention cleanup."""
    try:
        result = pcap_analyzer.cleanup_old_pcaps(retention_days)
        return {
            "status": "success",
            **result,
        }
    except Exception as e:
        logger.error("Error during PCAP cleanup: %s", e)
        raise HTTPException(status_code=500, detail="PCAP cleanup failed due to an internal error.")
