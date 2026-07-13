from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional, Dict, Any, List
from database.database import get_db
from database.models import Alert
from pydantic import BaseModel
from datetime import datetime, timezone

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])

class AlertResponse(BaseModel):
    id: int
    timestamp: str
    level: str
    type: str
    source_ip: Optional[str]
    description: str
    details: Optional[str]
    is_resolved: bool

    class Config:
        orm_mode = True

@router.get("", response_model=Dict[str, Any])
def list_alerts(
    limit: int = 100,
    offset: int = 0,
    level: Optional[str] = None,
    type: Optional[str] = None,
    resolved: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """
    Get a list of security alerts with pagination and filtering.
    """
    try:
        query = db.query(Alert)
        
        if level is not None and level != "ALL":
            query = query.filter(Alert.level == level)
        if type is not None and type != "ALL":
            query = query.filter(Alert.type == type)
        if resolved is not None:
            query = query.filter(Alert.is_resolved == resolved)
            
        total = query.count()
        alerts = query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()
        
        formatted_alerts = []
        for alert in alerts:
            formatted_alerts.append({
                "id": alert.id,
                "timestamp": alert.timestamp.replace(tzinfo=timezone.utc).isoformat() if alert.timestamp else datetime.now(timezone.utc).isoformat(),
                "level": alert.level,
                "type": alert.type,
                "source_ip": alert.source_ip,
                "description": alert.description,
                "details": alert.details,
                "is_resolved": alert.is_resolved
            })
            
        return {
            "status": "success",
            "total": total,
            "limit": limit,
            "offset": offset,
            "alerts": formatted_alerts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query alerts: {str(e)}")

@router.patch("/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    """
    Mark a security alert as resolved.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    try:
        alert.is_resolved = True
        db.commit()
        return {"status": "success", "message": f"Alert {alert_id} resolved"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to resolve alert: {str(e)}")
