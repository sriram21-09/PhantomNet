from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from database.database import get_db
from database.models import PacketLog
from datetime import datetime, timedelta
import random

router = APIRouter(prefix="/api/v1/attribution", tags=["AttackAttribution"])


def _detect_tools(protocol: str, attack_type: str, threat_score: float):
    """Heuristic tool detection based on protocol and attack patterns."""
    tools = []
    if protocol in ("TCP", "SSH") and threat_score > 60:
        tools.append("Nmap")
    if protocol == "SSH" and attack_type in ("MALICIOUS", "Brute Force"):
        tools.append("Hydra")
    if threat_score > 80:
        tools.append("Metasploit")
    if protocol == "HTTP" and threat_score > 50:
        tools.append("Nikto")
    if protocol == "FTP" and threat_score > 40:
        tools.append("Custom Script")
    if not tools:
        tools.append("Unknown Scanner")
    return tools


def _infer_intent(attack_type: str, event_count: int, threat_score: float):
    """Infer attacker intent from behaviour patterns."""
    if threat_score > 85 or attack_type == "MALICIOUS":
        if event_count > 20:
            return "Exfiltration"
        return "Exploitation"
    if event_count > 10:
        return "Lateral Movement"
    return "Reconnaissance"


def _sophistication(threat_score: float, event_count: int):
    """Classify attacker sophistication."""
    if threat_score > 90 and event_count > 15:
        return {"level": "Advanced (State-Actor)", "class": "level-vhigh", "score": 95}
    if threat_score > 70:
        return {"level": "Intermediate (Organized)", "class": "level-high", "score": 75}
    return {"level": "Amateur (Script Kiddie)", "class": "level-low", "score": 30}


def _attack_progression(events):
    """Determine which attack stages the attacker has reached."""
    stages = [
        {"name": "RECON", "active": False},
        {"name": "EXPLOIT", "active": False},
        {"name": "LATERAL", "active": False},
        {"name": "EXFIL", "active": False},
    ]
    if len(events) > 0:
        stages[0]["active"] = True  # At least recon
    high_events = [e for e in events if (e.threat_score or 0) > 60]
    if high_events:
        stages[1]["active"] = True
    critical_events = [e for e in events if (e.threat_score or 0) > 80]
    if critical_events and len(events) > 10:
        stages[2]["active"] = True
    if critical_events and len(events) > 20:
        stages[3]["active"] = True
    return stages


@router.get("/profile/{ip}")
def get_attacker_profile(ip: str, db: Session = Depends(get_db)):
    """Full attacker profile for a given IP address."""
    events = (
        db.query(PacketLog)
        .filter(PacketLog.src_ip == ip)
        .order_by(PacketLog.timestamp.desc())
        .limit(200)
        .all()
    )

    if not events:
        return {"status": "not_found", "ip": ip}

    latest = events[0]
    oldest = events[-1]
    avg_score = sum((e.threat_score or 0) for e in events) / len(events)
    max_score = max((e.threat_score or 0) for e in events)
    protocols_used = list(set(e.protocol for e in events if e.protocol))
    attack_types = list(set(e.attack_type for e in events if e.attack_type))

    soph = _sophistication(max_score, len(events))
    tools = _detect_tools(latest.protocol or "TCP", latest.attack_type or "BENIGN", max_score)
    intent = _infer_intent(latest.attack_type or "BENIGN", len(events), max_score)
    progression = _attack_progression(events)

    confidence = min(95, int(avg_score * 0.7 + len(events) * 0.3 + 10))

    return {
        "status": "success",
        "ip": ip,
        "profile": {
            "sophistication": soph,
            "tools_detected": tools,
            "intent": intent,
            "protocols": protocols_used,
            "attack_types": attack_types,
            "persistence": len(events) > 15,
        },
        "timeline": {
            "first_seen": oldest.timestamp.isoformat() if oldest.timestamp else None,
            "last_seen": latest.timestamp.isoformat() if latest.timestamp else None,
            "total_events": len(events),
            "avg_threat_score": round(avg_score, 1),
            "max_threat_score": round(max_score, 1),
        },
        "progression": progression,
        "confidence": confidence,
    }


@router.get("/top-attackers")
def get_top_attackers(limit: int = 10, db: Session = Depends(get_db)):
    """Return top attackers ranked by event count and threat score."""
    since = datetime.utcnow() - timedelta(hours=24)

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

    attackers = []
    for row in results:
        avg = float(row.avg_score) if row.avg_score else 0
        mx = float(row.max_score) if row.max_score else 0
        soph = _sophistication(mx, row.event_count)
        attackers.append({
            "ip": row.src_ip,
            "event_count": row.event_count,
            "avg_threat_score": round(avg, 1),
            "max_threat_score": round(mx, 1),
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "sophistication": soph,
        })

    return {"status": "success", "count": len(attackers), "attackers": attackers}
