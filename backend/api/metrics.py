from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any, List
from datetime import datetime

# Local imports
from database.database import get_db
from database.models import PacketLog

router = APIRouter(
    prefix="/api",
    tags=["Metrics"]
)

@router.get("/threat-metrics")
def get_threat_metrics(db: Session = Depends(get_db)):
    """
    Returns aggregated threat metrics for the dashboard.
    Expected format by frontend:
    {
      "threatLevel": int (0-100),
      "anomalyScore": int (0-100)
    }
    """
    try:
        # Fetch recent logs to calculate current threat state
        # using last 50 logs as a rolling window for "live" status
        recent_logs = (
            db.query(PacketLog)
            .order_by(PacketLog.timestamp.desc())
            .limit(50)
            .all()
        )

        if not recent_logs:
            return {
                "threatLevel": 0,
                "anomalyScore": 0,
                "activeThreats": 0
            }

        # Calculate Threat Level (Average of threat_score)
        total_threat_score = sum(log.threat_score or 0 for log in recent_logs)
        avg_threat_score = total_threat_score / len(recent_logs)

        # Calculate Anomaly Score (Use threat_score as proxy for now as anomaly_score column is missing)
        total_anomaly_score = sum(log.threat_score or 0 for log in recent_logs)
        avg_anomaly_score = total_anomaly_score / len(recent_logs)

        # Count Active Threats (High Severity)
        active_threats = sum(1 for log in recent_logs if (log.threat_score or 0) > 70)

        return {
            "threatLevel": int(avg_threat_score),
            "anomalyScore": (avg_anomaly_score / 100.0) if avg_anomaly_score > 1 else avg_anomaly_score,
            "activeThreats": active_threats
        }

    except Exception as e:
        print(f"[API ERROR] Failed to calculate threat metrics: {e}")
        return {
            "threatLevel": 0,
            "anomalyScore": 0,
            "error": str(e)
        }
