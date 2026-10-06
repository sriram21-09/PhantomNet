from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from database.database import get_db
from database.models import PacketLog
from middleware.auth import get_current_user
from datetime import datetime, timedelta
import math

router = APIRouter(
    prefix="/api/v1/predictive",
    tags=["Predictive"],
    dependencies=[Depends(get_current_user)],
)


def _generate_forecast(hourly_counts: list, hours_ahead: int = 6):
    """
    Statistical exponential smoothing forecast from hourly event volume.
    Applies single exponential smoothing (alpha=0.4) with linear trend projection.
    """
    if not hourly_counts:
        return [{"hour": i, "predicted": 0} for i in range(hours_ahead)]

    alpha = 0.4
    smoothed = hourly_counts[0]
    for val in hourly_counts[1:]:
        smoothed = alpha * val + (1 - alpha) * smoothed

    forecast = []
    trend = (hourly_counts[-1] - hourly_counts[0]) / max(len(hourly_counts), 1)
    for i in range(hours_ahead):
        predicted = max(0, smoothed + trend * (i + 1))
        now = datetime.utcnow() + timedelta(hours=i + 1)
        forecast.append(
            {
                "time": now.strftime("%H:%M"),
                "predicted": round(predicted, 1),
            }
        )

    return forecast


@router.get("/forecast")
def get_forecast(db: Session = Depends(get_db)):
    """Return time-series statistical forecast for the next 6 hours."""
    now = datetime.utcnow()
    hourly_counts = []

    for i in range(12, 0, -1):
        start = now - timedelta(hours=i)
        end = now - timedelta(hours=i - 1)
        count = (
            db.query(func.count(PacketLog.id))
            .filter(PacketLog.timestamp >= start, PacketLog.timestamp < end)
            .scalar()
        ) or 0
        hourly_counts.append(count)

    # Build historical + forecast data
    historical = []
    for i, count in enumerate(hourly_counts):
        t = now - timedelta(hours=12 - i)
        historical.append(
            {
                "time": t.strftime("%H:%M"),
                "current": count,
            }
        )

    forecast = _generate_forecast(hourly_counts, hours_ahead=6)

    # Trend direction
    if len(hourly_counts) >= 2:
        recent_avg = sum(hourly_counts[-3:]) / 3
        older_avg = sum(hourly_counts[:3]) / 3
        if recent_avg > older_avg * 1.15:
            trend = "RISING"
        elif recent_avg < older_avg * 0.85:
            trend = "FALLING"
        else:
            trend = "STABLE"
    else:
        trend = "STABLE"

    return {
        "status": "success",
        "has_data": sum(hourly_counts) > 0,
        "historical": historical,
        "forecast": forecast,
        "trend": trend,
        "total_predicted_next_hour": forecast[0]["predicted"] if forecast else 0,
        "model": "Statistical Protocol Frequency Analysis",
        "method": "Statistical Exponential Smoothing (alpha=0.4)",
    }


def _classify_risk(risk_score: float) -> str:
    """Canonical severity cutoffs: CRITICAL >= 80, HIGH >= 60, MEDIUM >= 40, LOW < 40."""
    if risk_score >= 80:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH"
    if risk_score >= 40:
        return "MEDIUM"
    return "LOW"


@router.get("/risk-score")
def get_risk_score(db: Session = Depends(get_db)):
    """Aggregate risk score across all honeypots using canonical thresholds."""
    since = datetime.utcnow() - timedelta(minutes=30)

    result = (
        db.query(
            func.avg(PacketLog.threat_score).label("avg"),
            func.max(PacketLog.threat_score).label("max"),
            func.count(PacketLog.id).label("count"),
        )
        .filter(PacketLog.timestamp >= since)
        .first()
    )

    avg_score = float(result.avg) if result and result.avg else 0.0
    max_score = float(result.max) if result and result.max else 0.0
    count = result.count if result and result.count else 0

    if count == 0:
        return {
            "status": "success",
            "has_data": False,
            "risk_score": 0.0,
            "risk_level": "LOW",
            "avg_threat_score": 0.0,
            "max_threat_score": 0.0,
            "event_count": 0,
            "window_minutes": 30,
        }

    # Normalize scores to 0-100 for risk calculation if they come as 0.0-1.0
    avg_score_scaled = avg_score * 100 if avg_score <= 1.0 else avg_score
    max_score_scaled = max_score * 100 if max_score <= 1.0 else max_score

    # Weighted risk: 50% avg score + 30% max score + 20% volume factor
    volume_factor = min(100, count * 2)
    risk_score = round(avg_score_scaled * 0.5 + max_score_scaled * 0.3 + volume_factor * 0.2, 1)

    level = _classify_risk(risk_score)

    return {
        "status": "success",
        "has_data": True,
        "risk_score": risk_score,
        "risk_level": level,
        "avg_threat_score": round(avg_score if avg_score <= 1.0 else avg_score / 100, 3),
        "max_threat_score": round(max_score if max_score <= 1.0 else max_score / 100, 3),
        "event_count": count,
        "window_minutes": 30,
    }


@router.get("/next-attack")
def get_next_attack_prediction(db: Session = Depends(get_db)):
    """Estimate the most targeted honeypot based on recent protocol frequency."""
    since = datetime.utcnow() - timedelta(hours=2)

    # Find most targeted protocol in the past 2 hours
    results = (
        db.query(
            PacketLog.protocol,
            func.count(PacketLog.id).label("count"),
            func.avg(PacketLog.threat_score).label("avg_score"),
        )
        .filter(PacketLog.timestamp >= since)
        .group_by(PacketLog.protocol)
        .order_by(func.count(PacketLog.id).desc())
        .limit(5)
        .all()
    )

    target_map = {
        "SSH": {"name": "SSH HONEYPOT", "port": 2222},
        "HTTP": {"name": "HTTP HONEYPOT", "port": 8080},
        "FTP": {"name": "FTP HONEYPOT", "port": 2121},
        "SMTP": {"name": "SMTP HONEYPOT", "port": 2525},
        "UDP": {"name": "UDP SERVICE", "port": 53},
        "TCP": {"name": "NETWORK PERIMETER", "port": 80},
    }

    if results:
        top = results[0]
        target_info = target_map.get(
            top.protocol, {"name": f"{top.protocol} SERVICE", "port": 0}
        )
        avg_score = float(top.avg_score or 0.0)
        avg_score_scaled = avg_score * 100 if avg_score <= 1.0 else avg_score
        confidence = min(
            95, max(40, int(avg_score_scaled * 0.5 + min(50, top.count * 2)))
        )
        est_minutes = max(3, int(30 - min(25, top.count)))
        return {
            "status": "success",
            "has_data": True,
            "target": f"{target_info['name']} (PORT {target_info['port']})",
            "confidence": confidence,
            "estimated_minutes": est_minutes,
            "model": "Statistical Protocol Frequency Analysis",
            "method": "Recent Event Frequency Ranking",
            "window_hours": 2,
        }
    else:
        return {
            "status": "success",
            "has_data": False,
            "target": "Insufficient data",
            "confidence": None,
            "estimated_minutes": None,
            "model": "Statistical Protocol Frequency Analysis",
            "method": "Recent Event Frequency Ranking",
            "window_hours": 2,
        }
