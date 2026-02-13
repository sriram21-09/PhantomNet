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
        Returns daily attack counts for the last N days.
        """
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Aggregate by Date (using SQLite/Postgres compatible approx)
        # For simplicity in hybrid env, we fetch and aggregate or use specific func.
        # Postgres: func.date_trunc('day', PacketLog.timestamp)
        # SQLite: func.strftime('%Y-%m-%d', PacketLog.timestamp)
        
        # Using Python aggregation for DB agnosticism if vol occurs, 
        # but SQL is better. Let's try flexible grouping.
        
        results = (
            self.db.query(
                func.date(PacketLog.timestamp).label('date'),
                func.count(PacketLog.id).label('count')
            )
            .filter(PacketLog.timestamp >= start_date)
            .group_by('date')
            .order_by('date')
            .all()
        )
        
        return [{"date": str(r.date), "count": r.count} for r in results]

    def detect_brute_force(self, protocol: str, window_minutes: int = 10, threshold: int = 5) -> List[Dict[str, Any]]:
        """
        Identifies IPs with high frequency of events in short window.
        """
        since = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        results = (
            self.db.query(
                PacketLog.src_ip,
                func.count(PacketLog.id).label('attempt_count')
            )
            .filter(
                and_(
                    PacketLog.timestamp >= since,
                    PacketLog.protocol == protocol.upper()
                )
            )
            .group_by(PacketLog.src_ip)
            .having(func.count(PacketLog.id) >= threshold)
            .order_by(desc('attempt_count'))
            .limit(20)
            .all()
        )
        
        return [{"src_ip": r.src_ip, "count": r.attempt_count} for r in results]

    def get_protocol_stats(self, protocol: str) -> Dict[str, Any]:
        """
        Returns summary stats for a protocol.
        """
        total = self.db.query(func.count(PacketLog.id)).filter(PacketLog.protocol == protocol.upper()).scalar()
        
        top_attackers = (
            self.db.query(
                PacketLog.src_ip,
                func.count(PacketLog.id).label('count')
            )
            .filter(PacketLog.protocol == protocol.upper())
            .group_by(PacketLog.src_ip)
            .order_by(desc('count'))
            .limit(5)
            .all()
        )
        
        return {
            "total_events": total,
            "top_attackers": [{"ip": r.src_ip, "count": r.count} for r in top_attackers]
        }

    def close(self):
        self.db.close()
