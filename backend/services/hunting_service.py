from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc
from database.models import PacketLog, Event, IOC, InvestigationCase, CaseEvidence, SearchHistory
from datetime import datetime, timedelta
import re
import json

class HuntingService:
    def __init__(self, db: Session):
        self.db = db

    def search_events(self, query_params: dict):
        """
        Advanced search for events across PacketLog and (optionally) Honeypot Event tables.
        query_params format:
        {
            "logic": "AND",
            "conditions": [
                {"field": "src_ip", "operator": "equals", "value": "1.2.3.4"},
                {"field": "threat_score", "operator": "greater_than", "value": 80}
            ],
            "limit": 100,
            "offset": 0
        }
        """
        logic = query_params.get("logic", "AND")
        conditions = query_params.get("conditions", [])
        limit = query_params.get("limit", 100)
        offset = query_params.get("offset", 0)

        # Base query on PacketLog (most common search target)
        query = self.db.query(PacketLog)

        filters = []
        for cond in conditions:
            f = self._build_filter(PacketLog, cond)
            if f is not None:
                filters.append(f)

        if filters:
            if logic == "OR":
                query = query.filter(or_(*filters))
            elif logic == "NOT":
                query = query.filter(and_(*[~f for f in filters if f is not None]))
            else:
                query = query.filter(and_(*filters))

        total = query.count()
        results = query.order_by(desc(PacketLog.timestamp)).offset(offset).limit(limit).all()

        # Record Search History
        try:
            history = SearchHistory(
                query_json=json.dumps(query_params),
                result_count=total
            )
            self.db.add(history)
            self.db.commit()
        except:
            self.db.rollback()

        return {
            "total": total,
            "results": [self._format_packet_log(log) for log in results]
        }

    def _build_filter(self, model, cond):
        field_name = cond.get("field")
        operator = cond.get("operator")
        value = cond.get("value")

        if not hasattr(model, field_name):
            return None

        column = getattr(model, field_name)

        if operator == "equals":
            return column == value
        elif operator == "not_equals":
            return column != value
        elif operator == "contains":
            return column.ilike(f"%{value}%")
        elif operator == "starts_with":
            return column.ilike(f"{value}%")
        elif operator == "greater_than":
            return column > value
        elif operator == "less_than":
            return column < value
        elif operator == "between":
            if isinstance(value, list) and len(value) == 2:
                return column.between(value[0], value[1])
        elif operator == "in_list":
            if isinstance(value, list):
                return column.in_(value)
        return None

    def _format_packet_log(self, log):
        return {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "src_port": log.src_port,
            "dst_port": log.dst_port,
            "protocol": log.protocol,
            "threat_score": log.threat_score,
            "threat_level": log.threat_level,
            "attack_type": log.attack_type,
            "is_malicious": log.is_malicious
        }

    def extract_iocs(self, text: str):
        """
        Regex-based extraction of IOCs from raw payload or log text.
        """
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        
        iocs = []
        
        # IPs
        for ip in re.findall(ip_pattern, text):
            if ip not in ["127.0.0.1", "0.0.0.0"]:
                iocs.append({"type": "IP", "value": ip})
                
        # Domains
        for domain in re.findall(domain_pattern, text):
            # Simple heuristic to avoid common false positives
            if "." in domain and not domain.endswith((".py", ".js", ".css", ".html", ".png", ".jpg")):
                iocs.append({"type": "Domain", "value": domain.lower()})
                
        # Hashes (MD5)
        for md5 in re.findall(md5_pattern, text):
            iocs.append({"type": "MD5", "value": md5})
            
        return iocs

    def get_related_events(self, ip: str, honeypot_type: str = None, window_minutes: int = 1440):
        """
        Find events related to a specific IP or same honeypot within a time window.
        """
        start_time = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        query = self.db.query(PacketLog).filter(PacketLog.timestamp >= start_time)
        
        if ip and honeypot_type:
            # Correlation by both or either (IP is primary, Honeypot is secondary grouping)
            query = query.filter(or_(PacketLog.src_ip == ip, PacketLog.protocol == honeypot_type))
        elif ip:
            query = query.filter(PacketLog.src_ip == ip)
        elif honeypot_type:
            query = query.filter(PacketLog.protocol == honeypot_type)
            
        results = query.order_by(desc(PacketLog.timestamp)).limit(50).all()
        return [self._format_packet_log(log) for log in results]

    def detect_malicious_patterns(self, text: str):
        """
        Detect potential malicious signatures in raw data.
        """
        patterns = {
            "SQL Injection": [r"UNION\s+SELECT", r"OR\s+1=1", r"--;", r"DROP\s+TABLE"],
            "Cross-Site Scripting (XSS)": [r"<script", r"javascript:", r"onerror=", r"alert\("],
            "Directory Traversal": [r"\.\./\.\.", r"etc/passwd", r"windows/win\.ini"],
            "Command Injection": [r";\s*cat\b", r"\|\s*grep\b", r"&&\s*id\b", r"\$\(whoami\)"]
        }
        
        detected = []
        for category, regex_list in patterns.items():
            for regex in regex_list:
                if re.search(regex, text, re.IGNORECASE):
                    detected.append(category)
                    break # Only add category once
                    
        return detected
