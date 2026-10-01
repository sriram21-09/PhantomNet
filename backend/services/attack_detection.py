from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Local imports
from database.database import SessionLocal
from database.models import PacketLog


class AttackDetectionService:
    def __init__(self, db: Session = None):
        self.db = db or SessionLocal()

    def get_global_trends(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Returns continuous daily attack counts for the last N days with zero-filled missing dates.
        Bounded between 1 and 90 days.
        """
        days = max(1, min(days, 90))
        end_date = datetime.utcnow().date()
        start_date = end_date - timedelta(days=days - 1)
        start_datetime = datetime.combine(start_date, datetime.min.time())

        # Aggregate by Date (compatible with Postgres func index ix_packet_logs_date_trunc & SQLite)
        results = (
            self.db.query(
                func.date(PacketLog.timestamp).label("date"),
                func.count(PacketLog.id).label("count"),
            )
            .filter(PacketLog.timestamp >= start_datetime)
            .group_by(func.date(PacketLog.timestamp))
            .order_by(func.date(PacketLog.timestamp))
            .all()
        )

        counts_by_date = {str(r.date): r.count for r in results if r.date}

        # Build complete chronological series so every day in window has an authentic count
        series = []
        for i in range(days):
            day_str = (start_date + timedelta(days=i)).isoformat()
            series.append({
                "date": day_str,
                "count": counts_by_date.get(day_str, 0)
            })

        return series

    def detect_brute_force(
        self, protocol: str, window_minutes: int = 10, threshold: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Identifies IPs with high frequency of events in short window.
        """
        since = datetime.utcnow() - timedelta(minutes=window_minutes)

        results = (
            self.db.query(
                PacketLog.src_ip, func.count(PacketLog.id).label("attempt_count")
            )
            .filter(
                and_(
                    PacketLog.timestamp >= since, PacketLog.protocol == protocol.upper()
                )
            )
            .group_by(PacketLog.src_ip)
            .having(func.count(PacketLog.id) >= threshold)
            .order_by(desc("attempt_count"))
            .limit(20)
            .all()
        )

        return [{"src_ip": r.src_ip, "count": r.attempt_count} for r in results]

    def get_protocol_stats(self, protocol: str) -> Dict[str, Any]:
        """
        Returns summary stats for a protocol.
        """
        total = (
            self.db.query(func.count(PacketLog.id))
            .filter(PacketLog.protocol == protocol.upper())
            .scalar()
        )

        top_attackers = (
            self.db.query(PacketLog.src_ip, func.count(PacketLog.id).label("count"))
            .filter(PacketLog.protocol == protocol.upper())
            .group_by(PacketLog.src_ip)
            .order_by(desc("count"))
            .limit(5)
            .all()
        )

        return {
            "total_events": total,
            "top_attackers": [
                {"ip": r.src_ip, "count": r.count} for r in top_attackers
            ],
        }

    def close(self):
        self.db.close()
