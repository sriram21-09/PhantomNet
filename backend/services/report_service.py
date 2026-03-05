from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
import json
from database.models import PacketLog, Alert, TrafficStats, Event

class ReportService:
    def __init__(self, db: Session):
        self.db = db

    def get_report_data(self, template_type: str, filters: dict):
        """
        Aggregates data based on template type and filters.
        Filters example: {
            "date_range": "24h", 
            "honeypot": "ALL", 
            "threat_level": "ALL",
            "protocol": "ALL",
            "include_sections": ["Executive Summary", "Attack Timeline", ...]
        }
        """
        data = {
            "title": f"{template_type} Report",
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "filters_applied": filters,
            "sections": {}
        }

        # Apply time filter
        start_time = self._get_start_time(filters.get("date_range", "24h"))
        
        # Determine which sections to include
        requested_sections = filters.get("include_sections", [])
        if isinstance(requested_sections, str):
            requested_sections = [s.strip() for s in requested_sections.split(",") if s.strip()]
            
        if not requested_sections:
            # Default sections based on template
            if template_type == "Executive Summary":
                requested_sections = ["Executive Summary", "Top Attackers", "Geographic Distribution"]
            elif template_type == "Technical Detail":
                requested_sections = ["Attack Timeline", "Attack Patterns", "Event Logs"]
            elif template_type == "Compliance Report":
                requested_sections = ["Executive Summary", "Recommendations"]
            elif template_type == "Threat Intelligence Brief":
                requested_sections = ["Geographic Distribution", "Attack Patterns"]
            else:
                requested_sections = ["Executive Summary"]

        for section in requested_sections:
            if section == "Executive Summary":
                data["sections"]["Executive Summary"] = self._get_executive_summary(start_time, filters)
            elif section == "Attack Timeline":
                data["sections"]["Attack Timeline"] = self._get_attack_timeline(start_time, filters)
            elif section == "Geographic Distribution":
                data["sections"]["Geographic Distribution"] = self._get_geographic_distribution(start_time, filters)
            elif section == "Top Attackers":
                data["sections"]["Top Attackers"] = self._get_top_attackers(start_time, filters)
            elif section == "Attack Patterns":
                data["sections"]["Attack Patterns"] = self._get_attack_patterns(start_time, filters)
            elif section == "Event Logs":
                data["sections"]["Event Logs"] = self._get_event_logs(start_time, filters)
            elif section == "Recommendations":
                data["sections"]["Recommendations"] = self._get_recommendations(data["sections"])
        
        return data

    def _get_start_time(self, date_range: str):
        if date_range == "24h":
            return datetime.utcnow() - timedelta(hours=24)
        elif date_range == "7d":
            return datetime.utcnow() - timedelta(days=7)
        elif date_range == "30d":
            return datetime.utcnow() - timedelta(days=30)
        return datetime.utcnow() - timedelta(hours=24)

    def _apply_filters(self, query, filters):
        if filters.get("honeypot") and filters["honeypot"] != "ALL":
            # Assuming honeypot maps to protocol or a specific field if added
            query = query.filter(PacketLog.protocol == filters["honeypot"])
        
        if filters.get("threat_level") and filters["threat_level"] != "ALL":
            query = query.filter(PacketLog.threat_level == filters["threat_level"])
            
        if filters.get("protocol") and filters["protocol"] != "ALL":
            query = query.filter(PacketLog.protocol == filters["protocol"])
            
        return query

    def _get_executive_summary(self, start_time, filters):
        query = self.db.query(PacketLog).filter(PacketLog.timestamp >= start_time)
        query = self._apply_filters(query, filters)
        
        total_events = query.count()
        malicious_events = query.filter(PacketLog.threat_score >= 80).count()
        
        threat_levels = self.db.query(PacketLog.threat_level, func.count(PacketLog.id)).filter(
            PacketLog.timestamp >= start_time
        )
        if filters.get("protocol") and filters["protocol"] != "ALL":
            threat_levels = threat_levels.filter(PacketLog.protocol == filters["protocol"])
        
        threat_distribution = {level: count for level, count in threat_levels.group_by(PacketLog.threat_level).all() if level}

        return {
            "total_events": total_events,
            "malicious_events": malicious_events,
            "safety_score": round(((total_events - malicious_events) / total_events * 100), 2) if total_events > 0 else 100,
            "threat_distribution": threat_distribution
        }

    def _get_attack_timeline(self, start_time, filters):
        # Group by hour
        query = self.db.query(
            func.strftime("%Y-%m-%d %H:00:00", PacketLog.timestamp).label("hour"),
            func.count(PacketLog.id)
        ).filter(PacketLog.timestamp >= start_time)
        query = self._apply_filters(query, filters)
        
        results = query.group_by("hour").all()
        return [{"time": r[0], "count": r[1]} for r in results]

    def _get_geographic_distribution(self, start_time, filters):
        # We need Alert or PacketLog that has country info
        # Check Alert table if PacketLog doesn't have it
        countries = self.db.query(PacketLog.country, func.count(PacketLog.id)).filter(
            PacketLog.timestamp >= start_time,
            PacketLog.country.isnot(None)
        )
        countries = self._apply_filters(countries, filters)
        results = countries.group_by(PacketLog.country).all()

        return {country: count for country, count in results if country}

    def _get_top_attackers(self, start_time, filters):
        query = self.db.query(PacketLog.src_ip, func.count(PacketLog.id)).filter(
            PacketLog.timestamp >= start_time
        )
        query = self._apply_filters(query, filters)
        results = query.group_by(PacketLog.src_ip).order_by(func.count(PacketLog.id).desc()).limit(10).all()
        
        return [{"ip": r[0], "events": r[1]} for r in results]

    def _get_attack_patterns(self, start_time, filters):
        query = self.db.query(PacketLog.attack_type, func.count(PacketLog.id)).filter(
            PacketLog.timestamp >= start_time,
            PacketLog.attack_type.isnot(None)
        )
        query = self._apply_filters(query, filters)
        results = query.group_by(PacketLog.attack_type).all()
        
        return {pattern: count for pattern, count in results if pattern}

    def _get_event_logs(self, start_time, filters):
        query = self.db.query(PacketLog).filter(PacketLog.timestamp >= start_time)
        query = self._apply_filters(query, filters)
        logs = query.order_by(PacketLog.timestamp.desc()).limit(100).all()

        return [
            {
                "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": log.src_ip,
                "protocol": log.protocol,
                "threat_score": log.threat_score,
                "type": log.attack_type
            } for log in logs
        ]

    def _get_recommendations(self, current_sections):
        # Logic based on data
        recs = ["Ensure all honeypot nodes are monitoring standard ports."]
        
        exec_summary = current_sections.get("Executive Summary")
        if exec_summary and exec_summary.get("malicious_events", 0) > 100:
            recs.append("High malicious activity detected. Increase firewall strictness.")
            
        top_attackers = current_sections.get("Top Attackers")
        if top_attackers and len(top_attackers) > 0:
            recs.append(f"Consider blocking top offender: {top_attackers[0]['ip']}")
            
        return recs
