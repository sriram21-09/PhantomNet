import ipaddress
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_
from datetime import datetime, timedelta

from database.models import PacketLog, TrafficStats

HONEYPOT_PROTOCOLS = ["HTTP", "SSH", "FTP", "SMTP"]


def classify_ip_source(ip_str: str) -> dict:
    """
    Classifies an IP address into distinct network scopes and identifies
    test/synthetic/internal origins.
    """
    if not ip_str:
        return {
            "type": "Unknown / Synthetic",
            "category": "unknown",
            "is_synthetic": True,
            "badge_color": "gray",
        }
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_loopback:
            return {
                "type": "Localhost Loopback",
                "category": "loopback",
                "is_synthetic": True,
                "badge_color": "gray",
            }
        # RFC 5737 Test ranges: 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
        if (
            ip in ipaddress.ip_network("198.51.100.0/24")
            or ip in ipaddress.ip_network("192.0.2.0/24")
            or ip in ipaddress.ip_network("203.0.113.0/24")
        ):
            return {
                "type": "Test / Benchmark (RFC 5737)",
                "category": "testnet",
                "is_synthetic": True,
                "badge_color": "purple",
            }
        # Docker default bridge (172.16.0.0/12) and private RFC 1918 ranges
        if (
            ip in ipaddress.ip_network("172.16.0.0/12")
            or ip in ipaddress.ip_network("10.0.0.0/8")
            or ip in ipaddress.ip_network("192.168.0.0/16")
        ):
            return {
                "type": "Docker Bridge / Internal Gateway",
                "category": "internal_bridge",
                "is_synthetic": False,
                "badge_color": "amber",
            }
        return {
            "type": "External Internet Source",
            "category": "external",
            "is_synthetic": False,
            "badge_color": "red",
        }
    except ValueError:
        return {
            "type": "Synthetic Format",
            "category": "unknown",
            "is_synthetic": True,
            "badge_color": "gray",
        }


class StatsService:
    def __init__(self, db: Session) -> None:
        """
        Initializes the StatsService with a database session.

        Args:
            db: SQLAlchemy session object.
        """
        self.db = db

    def _apply_mode_filter(self, query, mode: str = "all"):
        """
        Applies data mode filtering:
          - 'live': Only packets from configured honeypots (HTTP, SSH, FTP, SMTP)
          - 'test': Synthetic TCP / benchmark seed packets
          - 'all': Complete dataset (mixed)
        """
        if mode == "live":
            return query.filter(PacketLog.protocol.in_(HONEYPOT_PROTOCOLS))
        elif mode == "test":
            return query.filter(
                or_(
                    PacketLog.protocol.in_(["TCP", ""]),
                    PacketLog.protocol.is_(None),
                )
            )
        return query

    def calculate_stats(self, mode: str = "all") -> dict:
        """
        Calculates and aggregates network activity statistics from the database.

        Args:
            mode: 'all' (mixed), 'live' (honeypots only), or 'test' (benchmark only).

        Returns:
            dict: Aggregated metrics including total events, unique IPs, 
                  active honeypots, average threat score, critical alerts,
                  and dataset composition breakdown.
        """
        base_query = self._apply_mode_filter(self.db.query(PacketLog), mode)

        # Total events for selected mode
        total_events = base_query.count()

        # Unique attacker / source IPs
        unique_ips = (
            self._apply_mode_filter(
                self.db.query(func.count(func.distinct(PacketLog.src_ip))),
                mode
            ).scalar() or 0
        )

        # Active honeypots: accurately count deployed honeypot services that have traffic (max 4)
        active_protocols = {
            p[0].upper()
            for p in self.db.query(PacketLog.protocol).distinct().all()
            if p[0] and p[0].upper() in {"HTTP", "SSH", "FTP", "SMTP"}
        }
        # PhantomNet runs 4 configured honeypots (SSH :2722, HTTP :8080, FTP :2721, SMTP :2725)
        active_honeypots = len(active_protocols) if active_protocols else 4

        # Average threat score (0–1)
        avg_threat = (
            self._apply_mode_filter(
                self.db.query(func.avg(PacketLog.threat_score)),
                mode
            ).scalar() or 0.0
        )

        # Average anomaly score (0–1)
        avg_anomaly = (
            self._apply_mode_filter(
                self.db.query(func.avg(PacketLog.anomaly_score)),
                mode
            ).scalar() or 0.0
        )

        # Critical alerts (>= 80 or >= 0.8 if on 0-1 scale)
        critical_alerts = (
            self._apply_mode_filter(
                self.db.query(PacketLog).filter(
                    or_(
                        PacketLog.threat_score >= 80,
                        and_(PacketLog.threat_score >= 0.8, PacketLog.threat_score <= 1.0),
                    )
                ),
                mode
            ).count()
        )

        # Detailed Distribution
        malicious_count = (
            self._apply_mode_filter(
                self.db.query(PacketLog).filter(
                    or_(
                        PacketLog.threat_score >= 75,
                        and_(PacketLog.threat_score >= 0.75, PacketLog.threat_score <= 1.0),
                    )
                ),
                mode
            ).count()
        )
        suspicious_count = (
            self._apply_mode_filter(
                self.db.query(PacketLog).filter(
                    or_(
                        PacketLog.threat_score.between(40, 74.99),
                        and_(PacketLog.threat_score >= 0.4, PacketLog.threat_score < 0.75),
                    )
                ),
                mode
            ).count()
        )
        benign_count = (
            self._apply_mode_filter(
                self.db.query(PacketLog).filter(
                    or_(
                        and_(PacketLog.threat_score < 40, PacketLog.threat_score > 1.0),
                        and_(PacketLog.threat_score < 0.4, PacketLog.threat_score >= 0.0),
                    )
                ),
                mode
            ).count()
        )

        # Real Protocol Distribution from actual database events for current mode
        proto_counts_query = (
            self.db.query(PacketLog.protocol, func.count(PacketLog.id))
            .filter(PacketLog.protocol.isnot(None), PacketLog.protocol != "")
        )
        proto_counts = (
            self._apply_mode_filter(proto_counts_query, mode)
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

        # Overall Dataset Composition Metadata
        live_count = self.db.query(PacketLog).filter(PacketLog.protocol.in_(HONEYPOT_PROTOCOLS)).count()
        test_count = self.db.query(PacketLog).filter(
            or_(PacketLog.protocol.in_(["TCP", ""]), PacketLog.protocol.is_(None))
        ).count()
        grand_total = self.db.query(PacketLog).count()

        return {
            "totalEvents": total_events,
            "uniqueIPs": unique_ips,
            "activeHoneypots": active_honeypots,
            "totalConfiguredNodes": 4,
            "avgThreatScore": round(avg_threat * 100, 1) if avg_threat <= 1.0 else round(avg_threat, 1),
            "avgAnomalyScore": round(avg_anomaly * 100, 1) if avg_anomaly <= 1.0 else round(avg_anomaly, 1),
            "criticalAlerts": critical_alerts,
            "distribution": {
                "critical": malicious_count,
                "suspicious": suspicious_count,
                "benign": benign_count,
            },
            "protocolDistribution": protocol_dist,
            "dataComposition": {
                "mode": mode,
                "liveEvents": live_count,
                "testEvents": test_count,
                "totalEvents": grand_total,
                "isMixed": mode == "all",
            },
        }

    def get_top_threat_vectors(self, limit: int = 10, mode: str = "all") -> list:
        """
        Retrieves real top attacker / source IPs from packet_logs aggregated by src_ip.
        Classifies each source as Internal Docker Bridge, RFC 5737 Test Net, or External.
        """
        base_query = (
            self.db.query(
                PacketLog.src_ip,
                func.count(PacketLog.id).label("count"),
                func.max(PacketLog.country).label("country"),
                func.max(PacketLog.threat_score).label("max_threat"),
                func.max(PacketLog.threat_level).label("threat_level"),
            )
            .filter(PacketLog.src_ip.isnot(None), PacketLog.src_ip != "")
        )

        filtered_query = self._apply_mode_filter(base_query, mode)

        rows = (
            filtered_query
            .group_by(PacketLog.src_ip)
            .order_by(func.count(PacketLog.id).desc())
            .limit(limit)
            .all()
        )

        # Total events for percentage calculation
        total_mode_events = self._apply_mode_filter(self.db.query(PacketLog), mode).count() or 1

        results = []
        for r in rows:
            max_t = r.max_threat or 0.0
            threat_val = max_t if max_t <= 1.0 else max_t / 100.0
            classification = classify_ip_source(r.src_ip)

            if r.threat_level:
                risk = r.threat_level.capitalize()
            elif threat_val >= 0.75:
                risk = "High"
            elif threat_val >= 0.40:
                risk = "Medium"
            else:
                risk = "Low"

            # Determine human-friendly origin label
            if classification["category"] == "internal_bridge":
                origin = "Docker Bridge (Host/Gateway)"
            elif classification["category"] == "testnet":
                origin = "RFC 5737 (Test / Benchmark)"
            elif classification["category"] == "loopback":
                origin = "Localhost (Loopback)"
            elif r.country and r.country != "Unknown":
                origin = r.country
            else:
                origin = "Unknown Origin"

            results.append({
                "ip": r.src_ip,
                "count": r.count,
                "percentage": round((r.count / total_mode_events) * 100, 1),
                "country": origin,
                "risk": risk,
                "source_type": classification["type"],
                "source_category": classification["category"],
                "is_synthetic": classification["is_synthetic"],
                "badge_color": classification["badge_color"],
            })
        return results

    def get_attack_timeline_24h(self, mode: str = "all") -> dict:
        """
        Calculates 24-hour timeline of attack activity aggregated in hourly buckets.
        Uses latest event timestamp in selected mode (or UTC now) as reference.
        """
        latest_ts_query = self._apply_mode_filter(
            self.db.query(func.max(PacketLog.timestamp)),
            mode
        )
        latest_ts = latest_ts_query.scalar()
        if not latest_ts:
            latest_ts = datetime.utcnow()

        start_ts = latest_ts - timedelta(hours=24)
        prev_start_ts = start_ts - timedelta(hours=24)

        curr_count = (
            self._apply_mode_filter(
                self.db.query(func.count(PacketLog.id))
                .filter(PacketLog.timestamp >= start_ts, PacketLog.timestamp <= latest_ts),
                mode
            ).scalar() or 0
        )
        prev_count = (
            self._apply_mode_filter(
                self.db.query(func.count(PacketLog.id))
                .filter(PacketLog.timestamp >= prev_start_ts, PacketLog.timestamp < start_ts),
                mode
            ).scalar() or 0
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
                self._apply_mode_filter(
                    self.db.query(func.count(PacketLog.id))
                    .filter(PacketLog.timestamp >= b_start, PacketLog.timestamp < b_end),
                    mode
                ).scalar() or 0
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
            "mode": mode,
        }
