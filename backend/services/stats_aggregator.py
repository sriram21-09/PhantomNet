from typing import Optional, List, Dict, Any
import ipaddress
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_, case
from datetime import datetime, timedelta, timezone

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

    def _apply_filters(self, query, mode: str = "all", days: Optional[int] = None):
        """Applies data mode and optional time window filter."""
        query = self._apply_mode_filter(query, mode)
        if days is not None and days > 0:
            start_date = datetime.utcnow() - timedelta(days=days)
            query = query.filter(PacketLog.timestamp >= start_date)
        return query

    def calculate_stats(self, mode: str = "all", days: Optional[int] = None) -> dict:
        """
        Calculates and aggregates network activity statistics from the database.
        Uses a consolidated single-scan SQL aggregation query for high performance (ADV-DEF-08).

        Args:
            mode: 'all' (mixed), 'live' (honeypots only), or 'test' (benchmark only).
            days: Optional time window in days (7, 14, 30, 90) to scope analytics.

        Returns:
            dict: Aggregated metrics including total events, unique IPs, 
                  active honeypots, average threat score, critical alerts,
                  historical baseline delta, attack vector distribution, and dataset breakdown.
        """
        # 1. Consolidated Aggregation Query (executes in a single SQL scan)
        agg_query = self._apply_filters(
            self.db.query(
                func.count(PacketLog.id).label("total_events"),
                func.count(func.distinct(PacketLog.src_ip)).label("unique_ips"),
                func.avg(PacketLog.threat_score).label("avg_threat"),
                func.avg(PacketLog.anomaly_score).label("avg_anomaly"),
                func.count(
                    case((or_(
                        PacketLog.threat_score >= 80,
                        and_(PacketLog.threat_score >= 0.8, PacketLog.threat_score <= 1.0),
                    ), 1))
                ).label("critical_alerts"),
                func.count(
                    case((or_(
                        PacketLog.threat_score >= 75,
                        and_(PacketLog.threat_score >= 0.75, PacketLog.threat_score <= 1.0),
                    ), 1))
                ).label("malicious_count"),
                func.count(
                    case((or_(
                        PacketLog.threat_score.between(40, 74.99),
                        and_(PacketLog.threat_score >= 0.4, PacketLog.threat_score < 0.75),
                    ), 1))
                ).label("suspicious_count"),
                func.count(
                    case((or_(
                        and_(PacketLog.threat_score < 40, PacketLog.threat_score > 1.0),
                        and_(PacketLog.threat_score < 0.4, PacketLog.threat_score >= 0.0),
                    ), 1))
                ).label("benign_count"),
                func.count(case((PacketLog.anomaly_score > 0, 1))).label("total_anomalies"),
                func.count(
                    case((and_(PacketLog.anomaly_score >= 0.70, PacketLog.anomaly_score > 0), 1))
                ).label("high_anomalies"),
                func.count(
                    case((and_(PacketLog.anomaly_score >= 0.40, PacketLog.anomaly_score < 0.70), 1))
                ).label("med_anomalies"),
                func.count(case((PacketLog.protocol.in_(HONEYPOT_PROTOCOLS), 1))).label("live_count"),
                func.count(
                    case((or_(PacketLog.protocol.in_(["TCP", ""]), PacketLog.protocol.is_(None)), 1))
                ).label("test_count"),
            ),
            mode,
            days
        )
        row = agg_query.one()

        total_events = row.total_events or 0
        unique_ips = row.unique_ips or 0
        avg_threat = row.avg_threat or 0.0
        avg_anomaly = row.avg_anomaly or 0.0
        critical_alerts = row.critical_alerts or 0
        malicious_count = row.malicious_count or 0
        suspicious_count = row.suspicious_count or 0
        benign_count = row.benign_count or 0
        total_anomalies = row.total_anomalies or 0
        high_anomalies = row.high_anomalies or 0
        med_anomalies = row.med_anomalies or 0
        live_count = row.live_count or 0
        test_count = row.test_count or 0

        # 2. Protocol Distribution (single GROUP BY query)
        proto_counts_query = (
            self.db.query(PacketLog.protocol, func.count(PacketLog.id))
            .filter(PacketLog.protocol.isnot(None), PacketLog.protocol != "")
        )
        proto_counts = (
            self._apply_filters(proto_counts_query, mode, days)
            .group_by(PacketLog.protocol)
            .all()
        )
        total_proto = sum(cnt for _, cnt in proto_counts) or 1
        protocol_dist = []
        for proto, count in sorted(proto_counts, key=lambda x: x[1], reverse=True):
            if proto:
                protocol_dist.append({
                    "name": proto.upper(),
                    "protocol": proto.upper(),
                    "value": count,
                    "count": count,
                    "percentage": round((count / total_proto) * 100, 1),
                })

        active_protocols = {p["name"] for p in protocol_dist if p["name"] in {"HTTP", "SSH", "FTP", "SMTP"}}
        active_honeypots = len(active_protocols) if active_protocols else 4

        # 3. Attack Vector Distribution (single GROUP BY query on attack_type, ADV-DEF-07)
        vector_counts_query = (
            self.db.query(PacketLog.attack_type, func.count(PacketLog.id))
            .filter(PacketLog.attack_type.isnot(None), PacketLog.attack_type != "")
        )
        vector_counts = (
            self._apply_filters(vector_counts_query, mode, days)
            .group_by(PacketLog.attack_type)
            .all()
        )
        total_vectors = sum(cnt for _, cnt in vector_counts) or 1
        attack_vector_dist = [
            {
                "type": vec or "Unknown",
                "count": count,
                "percentage": round((count / total_vectors) * 100, 1),
            }
            for vec, count in sorted(vector_counts, key=lambda x: x[1], reverse=True)
            if vec
        ]

        # 4. Recent Anomalies (bounded query with LIMIT 10)
        recent_anomalies = self.get_recent_anomalies(limit=10, mode=mode, days=days)

        # 5. Comparative Historical Baseline (ADV-DEF-02: real comparative window delta)
        historical_baseline = {"days": days, "priorEvents": 0, "delta": None}
        if days is not None and days > 0:
            now = datetime.utcnow()
            baseline_start = now - timedelta(days=days * 2)
            baseline_end = now - timedelta(days=days)
            prior_query = self.db.query(func.count(PacketLog.id)).filter(
                and_(PacketLog.timestamp >= baseline_start, PacketLog.timestamp < baseline_end)
            )
            prior_events = self._apply_mode_filter(prior_query, mode).scalar() or 0
            delta = None
            if prior_events > 0:
                delta = round(((total_events - prior_events) / prior_events) * 100, 1)
            historical_baseline = {
                "days": days,
                "priorEvents": prior_events,
                "delta": delta,
            }

        grand_total = self.db.query(func.count(PacketLog.id)).scalar() or 0

        return {
            "totalEvents": total_events,
            "uniqueIPs": unique_ips,
            "activeHoneypots": active_honeypots,
            "totalConfiguredNodes": 4,
            "avgThreatScore": round(avg_threat * 100, 1) if avg_threat <= 1.0 else round(avg_threat, 1),
            "avgAnomalyScore": round(avg_anomaly * 100, 1) if avg_anomaly <= 1.0 else round(avg_anomaly, 1),
            "totalAnomalies": total_anomalies,
            "highSeverity": high_anomalies,
            "mediumSeverity": med_anomalies,
            "recentAnomalies": recent_anomalies,
            "criticalAlerts": critical_alerts,
            "distribution": {
                "critical": malicious_count,
                "suspicious": suspicious_count,
                "benign": benign_count,
            },
            "protocolDistribution": protocol_dist,
            "attackVectorDistribution": attack_vector_dist,
            "historicalBaseline": historical_baseline,
            "dataComposition": {
                "mode": mode,
                "days": days,
                "liveEvents": live_count,
                "testEvents": test_count,
                "totalEvents": grand_total,
                "isMixed": mode == "all",
            },
        }

    def get_recent_anomalies(self, limit: int = 10, mode: str = "all", days: Optional[int] = None) -> list:
        """
        Retrieves real recent anomalous events from packet_logs.
        """
        base_query = self.db.query(PacketLog).filter(PacketLog.anomaly_score > 0)
        filtered_query = self._apply_filters(base_query, mode, days)
        rows = filtered_query.order_by(PacketLog.timestamp.desc()).limit(limit).all()

        results = []
        for r in rows:
            score_val = r.anomaly_score or 0.0
            score_pct = round(score_val * 100, 1) if score_val <= 1.0 else round(score_val, 1)

            if score_val >= 0.8 or (r.threat_level and r.threat_level.upper() == "CRITICAL"):
                level = "CRITICAL"
            elif score_val >= 0.7 or (r.threat_level and r.threat_level.upper() == "HIGH"):
                level = "HIGH"
            elif score_val >= 0.4 or (r.threat_level and r.threat_level.upper() == "MEDIUM"):
                level = "MEDIUM"
            else:
                level = "LOW"

            proto = (r.protocol or "TCP").upper()
            src = r.src_ip or "Unknown"
            desc = f"Anomalous {proto} interaction detected from {src} (ML Isolation Forest score: {score_pct}%)"
            if r.attack_type and r.attack_type not in ("ALLOW", "UNKNOWN"):
                desc = f"{r.attack_type}: {desc}"

            results.append({
                "id": r.id,
                "timestamp": r.timestamp.replace(tzinfo=timezone.utc).isoformat() if r.timestamp else datetime.now(timezone.utc).isoformat(),
                "source_ip": src,
                "protocol": proto,
                "type": proto,
                "description": desc,
                "score": score_pct,
                "level": level,
                "threat_score": r.threat_score or 0.0,
                "threat_level": r.threat_level or "LOW",
            })
        return results

    def get_threat_summary(self, mode: str = "all") -> dict:
        """
        Calculates authoritative threat summary metrics aggregated at the database level:
          - activeThreats: Non-benign threats requiring attention (CRITICAL + HIGH + MEDIUM)
          - highSeverity: High & Critical severity threats (CRITICAL + HIGH)
          - criticalSeverity: Critical severity threats
          - mediumSeverity: Medium severity threats
          - lowSeverity: Low / benign events
          - totalEvents: Total event count for the selected mode
        """
        base_query = self._apply_mode_filter(self.db.query(PacketLog), mode)
        total_events = base_query.count()

        level_counts = dict(
            self._apply_mode_filter(
                self.db.query(PacketLog.threat_level, func.count(PacketLog.id)),
                mode
            )
            .group_by(PacketLog.threat_level)
            .all()
        )

        critical_count = level_counts.get("CRITICAL", 0)
        high_count = level_counts.get("HIGH", 0)
        medium_count = level_counts.get("MEDIUM", 0)
        low_count = level_counts.get("LOW", 0)

        # High severity summary card represents High + Critical
        high_severity_total = critical_count + high_count
        # Active threats are non-benign actionable events: critical + high + medium
        active_threats = high_severity_total + medium_count

        return {
            "status": "success",
            "mode": mode,
            "totalEvents": total_events,
            "activeThreats": active_threats,
            "highSeverity": high_severity_total,
            "criticalSeverity": critical_count,
            "mediumSeverity": medium_count,
            "lowSeverity": low_count,
            "breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
            }
        }

    def get_live_threat_alerts(self, limit: int = 10, mode: str = "all") -> list:
        """
        Retrieves real-time security alerts from packet_logs.
        Restricted to genuine security threats (CRITICAL, HIGH, or is_malicious=True).
        Never returns normal ALLOW/benign events.
        """
        base_query = self.db.query(PacketLog).filter(
            or_(
                PacketLog.threat_level.in_(["CRITICAL", "HIGH"]),
                PacketLog.is_malicious.is_(True),
            )
        )
        filtered_query = self._apply_mode_filter(base_query, mode)
        rows = filtered_query.order_by(PacketLog.timestamp.desc()).limit(limit).all()

        alerts = []
        for r in rows:
            level = (r.threat_level or "HIGH").upper()
            score_val = r.threat_score or 0.0
            score_pct = round(score_val * 100, 1) if 0.0 < score_val <= 1.0 else round(score_val, 1)

            # Resolve attack classification vs decision
            raw_attack = r.attack_type
            if raw_attack and raw_attack not in ("ALLOW", "ALERT", "BLOCK", "ERROR"):
                attack_type = raw_attack
            elif r.event:
                attack_type = r.event.upper()
            else:
                attack_type = "SUSPICIOUS_ACTIVITY"

            severity = "high" if level in ("CRITICAL", "HIGH") else "medium"
            proto = (r.protocol or "TCP").upper()
            src = r.src_ip or "Unknown"

            alerts.append({
                "id": r.id,
                "timestamp": r.timestamp.replace(tzinfo=timezone.utc).isoformat() if r.timestamp else datetime.now(timezone.utc).isoformat(),
                "time": r.timestamp.strftime("%H:%M:%S") if r.timestamp else "--:--",
                "source_ip": src,
                "protocol": proto,
                "attack_type": attack_type,
                "threat_level": level,
                "severity": severity,
                "score": score_pct,
                "message": f"{level}: {attack_type} from {src} ({proto})",
            })
        return alerts

    def get_recent_threat_indicators(self, limit: int = 20, mode: str = "all") -> list:
        """
        Retrieves recent telemetry indicators with authoritative backend fields:
        Time, Source IP, Threat Type, Score (0-100), and Severity (Critical/High/Medium/Low).
        Enforces clean separation between attack_type and decision.
        """
        base_query = self.db.query(PacketLog)
        filtered_query = self._apply_mode_filter(base_query, mode)
        rows = filtered_query.order_by(PacketLog.timestamp.desc()).limit(limit).all()

        indicators = []
        for r in rows:
            score_val = r.threat_score or 0.0
            score_pct = round(score_val * 100, 1) if 0.0 < score_val <= 1.0 else round(score_val, 1)

            threat_level = (r.threat_level or ("CRITICAL" if score_val >= 0.8 else ("HIGH" if score_val >= 0.6 else ("MEDIUM" if score_val >= 0.4 else "LOW")))).upper()

            raw_attack = r.attack_type
            if raw_attack in ("ALLOW", "ALERT", "BLOCK"):
                decision = raw_attack
                attack_type = "BENIGN" if (threat_level == "LOW" or score_val < 0.4) else (r.event.upper() if r.event else "SUSPICIOUS")
            elif raw_attack == "ERROR":
                decision = "ALERT" if threat_level in ("HIGH", "CRITICAL") else "ALLOW"
                attack_type = "BENIGN" if (threat_level == "LOW" or score_val < 0.4) else (r.event.upper() if r.event else "SUSPICIOUS")
            elif raw_attack:
                attack_type = raw_attack
                decision = "BLOCK" if score_val >= 0.8 else ("ALERT" if score_val >= 0.5 else "ALLOW")
            else:
                attack_type = "BENIGN" if (threat_level == "LOW" or score_val < 0.4) else (r.event.upper() if r.event else "SUSPICIOUS")
                decision = "BLOCK" if score_val >= 0.8 else ("ALERT" if score_val >= 0.5 else "ALLOW")

            indicators.append({
                "id": r.id,
                "time": r.timestamp.strftime("%H:%M:%S") if r.timestamp else "--:--",
                "timestamp": r.timestamp.replace(tzinfo=timezone.utc).isoformat() if r.timestamp else datetime.now(timezone.utc).isoformat(),
                "ip": r.src_ip or "Unknown",
                "type": attack_type,
                "attack_type": attack_type,
                "protocol": (r.protocol or "TCP").upper(),
                "port": r.dst_port or 0,
                "score": score_pct,
                "threat_score": score_val,
                "severity": threat_level.capitalize(),
                "threat_level": threat_level,
                "decision": decision,
                "is_malicious": bool(r.is_malicious or threat_level in ("HIGH", "CRITICAL")),
                "details": f"{attack_type} activity detected ({decision})" if attack_type != "BENIGN" else f"Normal {r.protocol or 'network'} traffic",
            })
        return indicators

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
