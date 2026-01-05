from sqlalchemy.orm import Session
from sqlalchemy import func
from app_models import Event
from datetime import datetime, timedelta

CRITICAL_THRESHOLD = 80  # Centralized, explicit

class StatsService:
    def __init__(self, db: Session):
        self.db = db

    def calculate_stats(self):
        """
        Returns live dashboard statistics derived directly from Events table.
        This is the single source of truth for /api/stats.
        """

        total_events = self.db.query(Event).count()

        unique_ips = (
            self.db.query(Event.source_ip)
            .distinct()
            .count()
        )

        avg_threat = (
            self.db.query(func.avg(Event.threat_score))
            .scalar()
        ) or 0

        critical_alerts = (
            self.db.query(Event)
            .filter(Event.threat_score >= CRITICAL_THRESHOLD)
            .count()
        )

        return {
            "totalEvents": total_events,
            "uniqueIPs": unique_ips,
            "avgThreatScore": round(avg_threat, 2),
            "criticalAlerts": critical_alerts
        }

    def get_hourly_trend(self):
        """
        Calculates event counts per hour for last 24 hours.
        """
        now = datetime.utcnow()
        start_time = now - timedelta(hours=24)

        logs = (
            self.db.query(Event.timestamp)
            .filter(Event.timestamp >= start_time)
            .all()
        )

        hours = {}
        for log in logs:
            hour = log.timestamp.strftime('%H')
            hours[hour] = hours.get(hour, 0) + 1

        result = [{"hour": h, "count": c} for h, c in hours.items()]
        result.sort(key=lambda x: x["hour"])

        return result
