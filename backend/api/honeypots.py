from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter(prefix="/api/honeypots", tags=["Honeypots"])


class HoneypotResponse(BaseModel):
    name: str
    port: int
    status: str
    last_seen: Optional[str]


@router.get("", response_model=List[HoneypotResponse])
def get_honeypot_status():
    """
    Expose honeypot status to frontend.
    Later this can be DB or heartbeat driven.
    """
    return [
        {
            "name": "SSH Honeypot",
            "port": 22,
            "status": "active",
            "last_seen": datetime.utcnow().isoformat(),
        },
        {
            "name": "HTTP Honeypot",
            "port": 80,
            "status": "active",
            "last_seen": datetime.utcnow().isoformat(),
        },
        {
            "name": "FTP Honeypot",
            "port": 21,
            "status": "inactive",
            "last_seen": None,
        },
        {
            "name": "SMTP Honeypot",
            "port": 25,
            "status": "active",
            "last_seen": datetime.utcnow().isoformat(),
        },
    ]
