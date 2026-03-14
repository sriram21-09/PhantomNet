"""
PhantomNet PCAP API Router
===========================
Endpoints for downloading PCAPs, viewing analysis results,
and retrieving capture statistics.
"""

import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import Event, PcapCapture
from services.pcap_analyzer import pcap_analyzer

router = APIRouter(prefix="/api/v1", tags=["PCAP Analysis"])

PCAP_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "..", "data", "pcaps"
)


# ------------------------------------------------------------------
# GET /api/v1/events/{id}/pcap — Download PCAP file
# ------------------------------------------------------------------
@router.get("/events/{event_id}/pcap")
def download_pcap(event_id: int, db: Session = Depends(get_db)):
    """Download the PCAP file associated with an event."""
    # Check event exists
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Look for PCAP on disk
    pcap_path = os.path.join(PCAP_DIR, f"{event_id}.pcap")
    if event.pcap_path and os.path.exists(event.pcap_path):
        pcap_path = event.pcap_path
    elif not os.path.exists(pcap_path):
        raise HTTPException(
            status_code=404, detail="PCAP file not found for this event"
        )

    return FileResponse(
        path=pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"phantomnet_event_{event_id}.pcap",
    )


# ------------------------------------------------------------------
# GET /api/v1/pcap/analysis/{id} — Get analysis results
# ------------------------------------------------------------------
@router.get("/pcap/analysis/{event_id}")
def get_pcap_analysis(event_id: int, db: Session = Depends(get_db)):
    """Return the deep packet analysis for a given event's PCAP."""
    # Try to find the PCAP
    pcap_path = os.path.join(PCAP_DIR, f"{event_id}.pcap")

    event = db.query(Event).filter(Event.id == event_id).first()
    if event and event.pcap_path and os.path.exists(event.pcap_path):
        pcap_path = event.pcap_path

    if os.path.exists(pcap_path):
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


# ------------------------------------------------------------------
# GET /api/v1/pcap/stats — Capture system statistics
# ------------------------------------------------------------------
@router.get("/pcap/stats")
def pcap_stats():
    """Return overall PCAP capture statistics."""
    stats = pcap_analyzer.get_stats()
    return {
        "status": "success",
        **stats,
    }


# ------------------------------------------------------------------
# POST /api/v1/pcap/capture/{event_id} — Trigger manual capture
# ------------------------------------------------------------------
@router.post("/pcap/capture/{event_id}")
def trigger_capture(event_id: int, duration: int = 60, db: Session = Depends(get_db)):
    """Manually trigger a packet capture for an event."""
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    result = pcap_analyzer.start_capture(event_id=event_id, duration=duration)
    return {
        "status": "success",
        "capture": result,
    }


# ------------------------------------------------------------------
# GET /api/v1/pcap/capture/{event_id}/status — Check capture status
# ------------------------------------------------------------------
@router.get("/pcap/capture/{event_id}/status")
def capture_status(event_id: int):
    """Check the status of an active or completed capture."""
    status = pcap_analyzer.get_capture_status(event_id)
    return {
        "status": "success",
        "capture": status,
    }


# ------------------------------------------------------------------
# POST /api/v1/pcap/cleanup — Manual retention cleanup
# ------------------------------------------------------------------
@router.post("/pcap/cleanup")
def run_cleanup(retention_days: int = 30):
    """Manually trigger PCAP retention cleanup."""
    result = pcap_analyzer.cleanup_old_pcaps(retention_days)
    return {
        "status": "success",
        **result,
    }
