"""
PhantomNet PCAP API Router
===========================
Endpoints for downloading PCAPs, viewing analysis results,
and retrieving capture statistics.
"""

import os
import logging
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import Event, PcapCapture
from services.pcap_analyzer import pcap_analyzer

logger = logging.getLogger("api.pcap")
router = APIRouter(prefix="/api/v1", tags=["PCAP Analysis"])

PCAP_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "data", "pcaps")
)


def _is_safe_pcap_path(path: str) -> bool:
    """Verify that a path is strictly inside the authorized PCAP directory."""
    abs_path = os.path.abspath(path)
    return abs_path.startswith(PCAP_DIR + os.sep) or abs_path == PCAP_DIR


# ------------------------------------------------------------------
# GET /api/v1/events/{id}/pcap — Download PCAP file
# ------------------------------------------------------------------
@router.get("/events/{event_id}/pcap")
def download_pcap(
    event_id: int = Path(..., ge=1, description="Event database ID"),
    db: Session = Depends(get_db),
):
    """Download the PCAP file associated with an event."""
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    pcap_path = os.path.join(PCAP_DIR, f"{event_id}.pcap")
    if event.pcap_path:
        if not _is_safe_pcap_path(event.pcap_path):
            logger.warning("Path traversal attempt detected on event %d: %s", event_id, event.pcap_path)
            raise HTTPException(status_code=403, detail="Invalid PCAP file path")
        if os.path.exists(event.pcap_path):
            pcap_path = event.pcap_path
        elif not os.path.exists(pcap_path):
            raise HTTPException(
                status_code=404, detail="PCAP file not found for this event"
            )
    elif not os.path.exists(pcap_path):
        raise HTTPException(
            status_code=404, detail="PCAP file not found for this event"
        )

    if not _is_safe_pcap_path(pcap_path):
        raise HTTPException(status_code=403, detail="Invalid PCAP file path")

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
    event_id: int = Path(..., ge=1, description="Event database ID"),
    db: Session = Depends(get_db),
):
    """Return the deep packet analysis for a given event's PCAP."""
    pcap_path = os.path.join(PCAP_DIR, f"{event_id}.pcap")

    event = db.query(Event).filter(Event.id == event_id).first()
    if event and event.pcap_path and _is_safe_pcap_path(event.pcap_path) and os.path.exists(event.pcap_path):
        pcap_path = event.pcap_path

    try:
        if os.path.exists(pcap_path) and _is_safe_pcap_path(pcap_path):
            analysis = pcap_analyzer.analyze_pcap(pcap_path)
            report = pcap_analyzer.generate_report(analysis)
            return {
                "status": "success",
                "event_id": event_id,
                "report": report,
            }

        # No PCAP on disk — return mock analysis for dashboard development
        mock = pcap_analyzer._mock_analysis()
        report = pcap_analyzer.generate_report(mock)
        return {
            "status": "success",
            "event_id": event_id,
            "source": "mock",
            "report": report,
        }
    except Exception as e:
        logger.error("Error analyzing PCAP for event %d: %s", event_id, e)
        raise HTTPException(status_code=500, detail="Failed to analyze PCAP file.")


# ------------------------------------------------------------------
# GET /api/v1/pcap/stats — Capture system statistics
# ------------------------------------------------------------------
@router.get("/pcap/stats")
def pcap_stats():
    """Return overall PCAP capture statistics."""
    try:
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
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

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
