from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta

from database.models import PacketLog, TrafficStats


class StatsService:
    def __init__(self, db: Session) -> None:
        """
        Initializes the StatsService with a database session.

        Args:
            db: SQLAlchemy session object.
        """
        self.db = db

    def calculate_stats(self) -> dict:
        """
        Calculates and aggregates network activity statistics from the database.

        Returns:
            dict: Aggregated metrics including total events, unique IPs, 
                  active honeypots, average threat score, and critical alerts.
        """
        # Total events
        total_events = self.db.query(PacketLog).count()

        # Unique attacker IPs
        unique_ips = (
            self.db.query(func.count(func.distinct(PacketLog.src_ip))).scalar() or 0
        )

        # Active honeypots (based on protocols seen)
        active_protocols = self.db.query(PacketLog.protocol).distinct().all()
        active_honeypots = len([p[0] for p in active_protocols])

        # Average threat score (0–1)
        avg_threat = self.db.query(func.avg(PacketLog.threat_score)).scalar() or 0.0

        # Critical alerts (>= 0.8)
        critical_alerts = (
            self.db.query(PacketLog).filter(PacketLog.threat_score >= 0.8).count()
        )

        return {
            "totalEvents": total_events,
            "uniqueIPs": unique_ips,
            "activeHoneypots": active_honeypots,
            "avgThreatScore": round(avg_threat * 100, 2),
            "criticalAlerts": critical_alerts,
        }
