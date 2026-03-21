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
            "name": "SSH",
            "port": 2222,
            "status": "active",
            "last_seen": datetime.utcnow().isoformat(),
        },
        {
            "name": "HTTP",
            "port": 8080,
            "status": "active",
            "last_seen": datetime.utcnow().isoformat(),
        },
        {
            "name": "FTP",
            "port": 2121,
            "status": "active",
            "last_seen": datetime.utcnow().isoformat(),
        },
        {
            "name": "SMTP",
            "port": 2525,
            "status": "active",
            "last_seen": datetime.utcnow().isoformat(),
        },
    ]
