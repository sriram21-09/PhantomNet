import socket
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from database.database import get_db, SessionLocal
from database.models import PacketLog

router = APIRouter(prefix="/api/honeypots", tags=["Honeypots"])


class HoneypotResponse(BaseModel):
    name: str
    port: int
    status: str
    last_seen: Optional[str]
    packet_count: int
    total_events: int


def check_port_status(host: str, port: int, fallback_host: str = "localhost", timeout: float = 1.0) -> str:
    """Checks if a port is open. Returns 'active' or 'inactive'."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "active"
    except Exception:
        pass

    try:
        with socket.create_connection((fallback_host, port), timeout=timeout):
            return "active"
    except Exception:
        return "inactive"


@router.get("", response_model=List[HoneypotResponse])
def get_honeypot_status(db: Session = Depends(get_db)):
    """
    Dynamically gets current honeypot container statuses and event counts.
    """
    local_session = False
    if not isinstance(db, Session):
        db = SessionLocal()
        local_session = True

    try:
        honeypot_configs = [
            {"name": "SSH", "port": 2222, "host": "ssh_honeypot"},
            {"name": "HTTP", "port": 8080, "host": "http_honeypot"},
            {"name": "FTP", "port": 2121, "host": "ftp_honeypot"},
            {"name": "SMTP", "port": 2525, "host": "smtp-honeypot"},
        ]

        results = []
        for cfg in honeypot_configs:
            name = cfg["name"]
            port = cfg["port"]
            host = cfg["host"]

            # 1. Check Port Status
            status = check_port_status(host, port)

            # 2. Get captured log counts
            count = db.query(PacketLog).filter(PacketLog.protocol == name).count()

            # 3. Get last active timestamp
            last_log = (
                db.query(PacketLog)
                .filter(PacketLog.protocol == name)
                .order_by(PacketLog.timestamp.desc())
                .first()
            )

            last_seen = None
            if last_log and last_log.timestamp:
                # SQLAlchemy returns a naive datetime in UTC, convert to aware
                dt = last_log.timestamp.replace(tzinfo=timezone.utc)
                last_seen = dt.isoformat()

            results.append(
                HoneypotResponse(
                    name=name,
                    port=port,
                    status=status,
                    last_seen=last_seen,
                    packet_count=count,
                    total_events=count,
                )
            )

        return results
    finally:
        if local_session:
            db.close()


@router.get("/status", response_model=List[HoneypotResponse])
def get_honeypot_status_alias(db: Session = Depends(get_db)):
    """
    Alias route for /api/honeypots/status to support all frontend components.
    """
    return get_honeypot_status(db)
