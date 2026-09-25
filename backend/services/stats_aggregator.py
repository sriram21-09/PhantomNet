from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_
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

        # Average anomaly score (0–1)
        avg_anomaly = self.db.query(func.avg(PacketLog.anomaly_score)).scalar() or 0.0

        # Critical alerts (>= 80 or >= 0.8 if on 0-1 scale)
        critical_alerts = (
            self.db.query(PacketLog).filter(
                or_(
                    PacketLog.threat_score >= 80,
                    and_(PacketLog.threat_score >= 0.8, PacketLog.threat_score <= 1.0),
                )
            ).count()
        )

        # Detailed Distribution
        malicious_count = (
            self.db.query(PacketLog).filter(
                or_(
                    PacketLog.threat_score >= 75,
                    and_(PacketLog.threat_score >= 0.75, PacketLog.threat_score <= 1.0),
                )
            ).count()
        )
        suspicious_count = (
            self.db.query(PacketLog).filter(
                or_(
                    PacketLog.threat_score.between(40, 74.99),
                    and_(PacketLog.threat_score >= 0.4, PacketLog.threat_score < 0.75),
                )
            ).count()
        )
        benign_count = (
            self.db.query(PacketLog).filter(
                or_(
                    and_(PacketLog.threat_score < 40, PacketLog.threat_score > 1.0),
                    and_(PacketLog.threat_score < 0.4, PacketLog.threat_score >= 0.0),
                )
            ).count()
        )

        # Real Protocol Distribution from actual database events
        proto_counts = (
            self.db.query(PacketLog.protocol, func.count(PacketLog.id))
            .filter(PacketLog.protocol.isnot(None), PacketLog.protocol != "")
            .group_by(PacketLog.protocol)
            .all()
        )
        total_proto = sum(cnt for _, cnt in proto_counts) or 1
        protocol_dist = []
        for proto, count in sorted(proto_counts, key=lambda x: x[1], reverse=True):
            if proto:
                protocol_dist.append({
                    "name": proto.upper(),
                    "value": count,
                    "percentage": round((count / total_proto) * 100, 1),
                })

        return {
            "totalEvents": total_events,
            "uniqueIPs": unique_ips,
            "activeHoneypots": active_honeypots,
            "avgThreatScore": round(avg_threat * 100, 1) if avg_threat <= 1.0 else round(avg_threat, 1),
            "avgAnomalyScore": round(avg_anomaly * 100, 1) if avg_anomaly <= 1.0 else round(avg_anomaly, 1),
            "criticalAlerts": critical_alerts,
            "distribution": {
                "critical": malicious_count,
                "suspicious": suspicious_count,
                "benign": benign_count,
            },
            "protocolDistribution": protocol_dist,
        }

    def get_top_threat_vectors(self, limit: int = 10) -> list:
        """
        Retrieves real top attacker IPs from packet_logs aggregated by src_ip.
        """
        rows = (
            self.db.query(
                PacketLog.src_ip,
                func.count(PacketLog.id).label("count"),
                func.max(PacketLog.country).label("country"),
                func.max(PacketLog.threat_score).label("max_threat"),
                func.max(PacketLog.threat_level).label("threat_level"),
            )
            .filter(PacketLog.src_ip.isnot(None), PacketLog.src_ip != "")
            .group_by(PacketLog.src_ip)
            .order_by(func.count(PacketLog.id).desc())
            .limit(limit)
            .all()
        )
        results = []
        for r in rows:
            max_t = r.max_threat or 0.0
            threat_val = max_t if max_t <= 1.0 else max_t / 100.0
            if r.threat_level:
                risk = r.threat_level.capitalize()
            elif threat_val >= 0.75:
                risk = "High"
            elif threat_val >= 0.40:
                risk = "Medium"
            else:
                risk = "Low"

            results.append({
                "ip": r.src_ip,
                "count": r.count,
                "country": r.country or "Unknown",
                "risk": risk,
            })
        return results

    def get_attack_timeline_24h(self) -> dict:
        """
        Calculates 24-hour timeline of attack activity aggregated in hourly buckets.
        Uses latest event timestamp or current UTC time as reference.
        """
        latest_ts = self.db.query(func.max(PacketLog.timestamp)).scalar()
        if not latest_ts:
            latest_ts = datetime.utcnow()

        start_ts = latest_ts - timedelta(hours=24)
        prev_start_ts = start_ts - timedelta(hours=24)

        curr_count = (
            self.db.query(func.count(PacketLog.id))
            .filter(PacketLog.timestamp >= start_ts, PacketLog.timestamp <= latest_ts)
            .scalar() or 0
        )
        prev_count = (
            self.db.query(func.count(PacketLog.id))
            .filter(PacketLog.timestamp >= prev_start_ts, PacketLog.timestamp < start_ts)
            .scalar() or 0
        )

        if prev_count > 0:
            trend_pct = round(((curr_count - prev_count) / prev_count) * 100, 1)
            trend_str = f"+{trend_pct}%" if trend_pct >= 0 else f"{trend_pct}%"
        else:
            trend_pct = 0.0
            trend_str = "+0.0%"

        # 24 1-hour buckets
        hourly_data = []
        for h in range(24):
            b_start = start_ts + timedelta(hours=h)
            b_end = b_start + timedelta(hours=1)
            cnt = (
                self.db.query(func.count(PacketLog.id))
                .filter(PacketLog.timestamp >= b_start, PacketLog.timestamp < b_end)
                .scalar() or 0
            )
            hourly_data.append({
                "time": b_start.strftime("%H:%M"),
                "events": cnt,
                "timestamp": b_start.isoformat(),
            })

        return {
            "timeline": hourly_data,
            "total24h": curr_count,
            "trend": f"{trend_str} vs yesterday",
            "trendValue": trend_pct,
        }
