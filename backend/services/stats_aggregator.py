from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from app_models import PacketLog, TrafficStats
from datetime import datetime, timedelta
import json

class StatsService:
    def __init__(self, db: Session):
        self.db = db

    def calculate_stats(self):
        """
        Aggregates raw logs into the TrafficStats cache.
        """
        # Analyze the last 24 hours
        now = datetime.utcnow()
        start_time = now - timedelta(hours=24)

        # 1. Total Attack Count
        total_attacks = self.db.query(PacketLog).filter(
            PacketLog.timestamp >= start_time,
            PacketLog.is_malicious == True
        ).count()

        # 2. Unique IP Count
        unique_ips = self.db.query(func.count(distinct(PacketLog.src_ip))).filter(
            PacketLog.timestamp >= start_time,
            PacketLog.is_malicious == True
        ).scalar()

        # 3. Attacks by Protocol ("Honeypot" Style)
        protocol_counts = self.db.query(
            PacketLog.protocol, func.count(PacketLog.id)
        ).filter(
            PacketLog.timestamp >= start_time,
            PacketLog.is_malicious == True
        ).group_by(PacketLog.protocol).all()

        type_dict = {p[0]: p[1] for p in protocol_counts}
        
        # 4. Save/Update Cache
        # Check if cache exists for the last 5 minutes
        latest_stat = self.db.query(TrafficStats).order_by(TrafficStats.timestamp.desc()).first()

        if not latest_stat or (now - latest_stat.last_updated).seconds > 300:
            new_stat = TrafficStats(
                timestamp=now,
                total_attacks=total_attacks,
                unique_attackers=unique_ips or 0,
                attacks_by_type=json.dumps(type_dict),
                last_updated=now
            )
            self.db.add(new_stat)
            self.db.commit()
            return new_stat
        
        return latest_stat

    def get_hourly_trend(self):
        """
        Calculates attacks per hour for the chart.
        (Done in Python to support BOTH PostgreSQL and SQLite safely)
        """
        now = datetime.utcnow()
        start_time = now - timedelta(hours=24)
        
        # 1. Get raw timestamps (Fast operation)
        logs = self.db.query(PacketLog.timestamp).filter(
            PacketLog.timestamp >= start_time,
            PacketLog.is_malicious == True
        ).all()

        # 2. Group by hour in Python
        hours = {}
        for log in logs:
            # log.timestamp is a datetime object
            h = log.timestamp.strftime('%H') # Returns "14", "09", etc.
            hours[h] = hours.get(h, 0) + 1

        # 3. Sort and Format
        result = [{"hour": h, "count": c} for h, c in hours.items()]
        # Sort by hour so the graph looks correct
        result.sort(key=lambda x: x['hour'])
        
        return result