import ipaddress
import logging
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from database.database import get_db
from database.models import PacketLog
from middleware.auth import get_current_user
from datetime import datetime, timedelta, timezone
import random

logger = logging.getLogger("api.attack_attribution")
router = APIRouter(
    prefix="/api/v1/attribution",
    tags=["AttackAttribution"],
    dependencies=[Depends(get_current_user)],
)


def _normalize_score(score: float | None) -> float:
    """Normalize threat score to canonical 0.0 - 1.0 scale."""
    if score is None:
        return 0.0
    if score > 1.0:
        return min(1.0, score / 100.0)
    return max(0.0, score)


def _detect_tools(protocol: str, attack_type: str, threat_score: float):
    """Evidence-based tool pattern detection based on protocol and packet indicators."""
    norm_score = _normalize_score(threat_score)
    tools = []
    if protocol in ("TCP", "SSH") and norm_score >= 0.60:
        tools.append("Port Scanner Pattern")
    if protocol == "SSH" and (attack_type in ("MALICIOUS", "Brute Force") or norm_score >= 0.60):
        tools.append("SSH Auth Scanner")
    if norm_score >= 0.80:
        tools.append("Exploitation Suite Pattern")
    if protocol == "HTTP" and norm_score >= 0.50:
        tools.append("Web Vulnerability Scanner")
    if protocol == "FTP" and norm_score >= 0.40:
        tools.append("Automated Script Pattern")
    if not tools:
        tools.append("Unclassified Traffic")
    return tools


def _infer_intent(attack_type: str, event_count: int, threat_score: float):
    """Infer observable intent from traffic volume and severity."""
    norm_score = _normalize_score(threat_score)
    if norm_score >= 0.80 or attack_type == "MALICIOUS":
        if event_count > 20:
            return "High-Volume Exploitation / Exfiltration"
        return "Active Exploitation"
    if event_count > 10:
        return "Reconnaissance / Lateral Movement"
    if norm_score >= 0.40:
        return "Targeted Scanning / Probe"
    return "Incidental Traffic / Reconnaissance"


def _sophistication(threat_score: float, event_count: int):
    """Classify threat severity tier based on canonical thresholds (0.80, 0.60, 0.40)."""
    norm_score = _normalize_score(threat_score)
    score_pct = round(norm_score * 100, 1)
    if norm_score >= 0.80 and event_count >= 10:
        return {"level": "Critical Threat (Persistent)", "class": "level-vhigh", "score": score_pct}
    if norm_score >= 0.60:
        return {"level": "High Threat (Targeted)", "class": "level-high", "score": score_pct}
    if norm_score >= 0.40:
        return {"level": "Medium Threat (Probing)", "class": "level-med", "score": score_pct}
    return {"level": "Low Threat / Insufficient Evidence", "class": "level-low", "score": score_pct}


def _attack_progression(events):
    """Determine observed attack stages using canonical thresholds."""
    stages = [
        {"name": "RECON", "active": False},
        {"name": "EXPLOIT", "active": False},
        {"name": "LATERAL", "active": False},
        {"name": "EXFIL", "active": False},
    ]
    if len(events) > 0:
        stages[0]["active"] = True  # Observed at least initial ingress
    
    high_events = [e for e in events if _normalize_score(e.threat_score) >= 0.60]
    if high_events:
        stages[1]["active"] = True
    
    critical_events = [e for e in events if _normalize_score(e.threat_score) >= 0.80]
    if critical_events and len(events) >= 5:
        stages[2]["active"] = True
    if critical_events and len(events) >= 15:
        stages[3]["active"] = True
    return stages


@router.get("/profile/{ip}")
def get_attacker_profile(
    ip: str = Path(..., min_length=1, max_length=50, description="IP address to profile"),
    db: Session = Depends(get_db)
):
    """Full attacker profile for a given IP address with verified data lineage."""
    ip_clean = ip.strip()
    try:
        ipaddress.ip_address(ip_clean)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address format: {ip}")

    events = (
        db.query(PacketLog)
        .filter(PacketLog.src_ip == ip_clean)
        .order_by(PacketLog.timestamp.desc())
        .limit(200)
        .all()
    )

    if not events:
        return {"status": "not_found", "ip": ip_clean, "detail": "No packet logs recorded for this IP address"}

    latest = events[0]
    oldest = events[-1]
    raw_scores = [_normalize_score(e.threat_score) for e in events]
    avg_score = sum(raw_scores) / len(raw_scores)
    max_score = max(raw_scores)
    protocols_used = sorted(list(set(e.protocol for e in events if e.protocol)))
    attack_types = sorted(list(set(e.attack_type for e in events if e.attack_type)))

    soph = _sophistication(max_score, len(events))
    tools = _detect_tools(
        latest.protocol or "TCP", latest.attack_type or "BENIGN", max_score
    )
    intent = _infer_intent(latest.attack_type or "BENIGN", len(events), max_score)
    progression = _attack_progression(events)

    confidence = min(95, max(10, int(avg_score * 60 + min(len(events), 35))))

    return {
        "status": "success",
        "ip": ip_clean,
        "evidence_source": "Database (packet_logs telemetry aggregation)",
        "profile": {
            "sophistication": soph,
            "tools_detected": tools,
            "intent": intent,
            "protocols": protocols_used,
            "attack_types": attack_types,
            "persistence": len(events) > 15,
        },
        "timeline": {
            "first_seen": oldest.timestamp.replace(tzinfo=timezone.utc).isoformat() if oldest.timestamp else None,
            "last_seen": latest.timestamp.replace(tzinfo=timezone.utc).isoformat() if latest.timestamp else None,
            "total_events": len(events),
            "avg_threat_score": round(avg_score, 3),
            "avg_threat_score_pct": round(avg_score * 100, 1),
            "max_threat_score": round(max_score, 3),
            "max_threat_score_pct": round(max_score * 100, 1),
        },
        "progression": progression,
        "confidence": confidence,
    }


@router.get("/top-attackers")
def get_top_attackers(
    limit: int = Query(10, ge=1, le=100, description="Max top attackers to return"),
    hours: int = Query(72, ge=1, le=720, description="Lookback window in hours"),
    db: Session = Depends(get_db)
):
    """Return top attackers ranked by event count and canonical threat score."""
    since = datetime.utcnow() - timedelta(hours=hours)

    results = (
        db.query(
            PacketLog.src_ip,
            func.count(PacketLog.id).label("event_count"),
            func.avg(PacketLog.threat_score).label("avg_score"),
            func.max(PacketLog.threat_score).label("max_score"),
            func.max(PacketLog.timestamp).label("last_seen"),
        )
        .filter(PacketLog.timestamp >= since)
        .group_by(PacketLog.src_ip)
        .order_by(desc("event_count"))
        .limit(limit)
        .all()
    )

    # Fallback if no events in specified window
    if not results:
        results = (
            db.query(
                PacketLog.src_ip,
                func.count(PacketLog.id).label("event_count"),
                func.avg(PacketLog.threat_score).label("avg_score"),
                func.max(PacketLog.threat_score).label("max_score"),
                func.max(PacketLog.timestamp).label("last_seen"),
            )
            .group_by(PacketLog.src_ip)
            .order_by(desc("event_count"))
            .limit(limit)
            .all()
        )

    attackers = []
    for row in results:
        raw_avg = float(row.avg_score) if row.avg_score else 0.0
        raw_mx = float(row.max_score) if row.max_score else 0.0
        norm_avg = _normalize_score(raw_avg)
        norm_mx = _normalize_score(raw_mx)
        soph = _sophistication(norm_mx, row.event_count)
        attackers.append(
            {
                "ip": row.src_ip,
                "event_count": row.event_count,
                "avg_threat_score": round(norm_avg, 3),
                "avg_threat_score_pct": round(norm_avg * 100, 1),
                "max_threat_score": round(norm_mx, 3),
                "max_threat_score_pct": round(norm_mx * 100, 1),
                "last_seen": row.last_seen.replace(tzinfo=timezone.utc).isoformat() if row.last_seen else None,
                "sophistication": soph,
            }
        )

    return {
        "status": "success",
        "evidence_source": "Database (packet_logs)",
        "count": len(attackers),
        "attackers": attackers
    }
