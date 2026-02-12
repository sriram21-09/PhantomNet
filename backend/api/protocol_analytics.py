from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

# Local imports
from database.database import get_db
from services.attack_detection import AttackDetectionService
from app_models import PacketLog

router = APIRouter(
    prefix="/api/v1/analytics",
    tags=["Analytics"]
)

@router.get("/ssh", response_model=Dict[str, Any])
async def get_ssh_analytics(db: Session = Depends(get_db)):
    """
    Returns SSH attack statistics including brute-force attempts.
    """
    service = AttackDetectionService(db)
    try:
        stats = service.get_protocol_stats("SSH")
        # Default threshold: 10 attempts in last 60 mins
        brute_force = service.detect_brute_force("SSH", window_minutes=60, threshold=10)
        
        return {
            "protocol": "SSH",
            "total_events": stats["total_events"],
            "top_attackers": stats["top_attackers"],
            "brute_force_suspects": brute_force
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/http", response_model=Dict[str, Any])
async def get_http_analytics(db: Session = Depends(get_db)):
    """
    Returns HTTP attack statistics.
    """
    service = AttackDetectionService(db)
    try:
        stats = service.get_protocol_stats("HTTP")
        # Default threshold: 50 requests in last 10 mins (DoS-like)
        flood_suspects = service.detect_brute_force("HTTP", window_minutes=10, threshold=50)
        
        return {
            "protocol": "HTTP",
            "total_requests": stats["total_events"],
            "top_ips": stats["top_attackers"],
            "potential_flooders": flood_suspects
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/trends", response_model=List[Dict[str, Any]])
async def get_attack_trends(days: int = Query(7, ge=1, le=30), db: Session = Depends(get_db)):
    """
    Returns daily attack volume for the last N days.
    """
    service = AttackDetectionService(db)
    try:
        return service.get_global_trends(days=days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
