from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc
from database.models import (
    PacketLog,
    Event,
    SearchHistory,
    IOC,
)
from datetime import datetime, timedelta, timezone
import re
import json
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger("services.hunting")

ALLOWED_SEARCH_FIELDS = {
    "id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "length",
    "threat_score",
    "threat_level",
    "attack_type",
    "is_malicious",
    "country",
    "city",
    "payload_content",
}

VALID_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "starts_with",
    "greater_than",
    "less_than",
    "greater_than_or_equal",
    "less_than_or_equal",
    "between",
    "in_list",
}


class HuntingService:
    def __init__(self, db: Session):
        self.db = db

    def search_events(self, query_params: dict, reference_time: Optional[datetime] = None):
        """
        Advanced search for events across PacketLog table.
        query_params format:
        {
            "logic": "AND",
            "conditions": [
                {"field": "src_ip", "operator": "equals", "value": "1.2.3.4"},
                {"field": "threat_score", "operator": "greater_than_or_equal", "value": 0.40}
            ],
            "limit": 100,
            "offset": 0
        }
        """
        logic = query_params.get("logic", "AND")
        conditions = query_params.get("conditions", [])
        limit = query_params.get("limit", 100)
        offset = query_params.get("offset", 0)

        query = self.db.query(PacketLog)

        filters = []
        for cond in conditions:
            f = self._build_filter(PacketLog, cond, reference_time=reference_time)
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
        results = (
            query.order_by(desc(PacketLog.timestamp)).offset(offset).limit(limit).all()
        )

        # Record Search History
        try:
            history = SearchHistory(
                query_json=json.dumps(query_params), result_count=total
            )
            self.db.add(history)
            self.db.commit()
        except Exception as exc:
            logger.warning("Failed to record search history: %s", exc)
            self.db.rollback()

        return {
            "total": total,
            "results": [self._format_packet_log(log) for log in results],
        }

    def _parse_timestamp_value(self, value: Any, reference_time: Optional[datetime] = None) -> datetime:
        """
        Deterministic parser converting relative durations or ISO strings to naive UTC datetimes.
        """
        if isinstance(value, datetime):
            return value.replace(tzinfo=None) if value.tzinfo else value

        val_str = str(value).strip()

        # Try ISO format
        try:
            iso_val = val_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_val)
            return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
        except (ValueError, TypeError):
            pass

        # Try relative format: 5m, 15m, 1h, 6h, 12h, 24h, 7d, 30d, 24h_ago
        rel_match = re.match(r"^(\d+)\s*([smhdwSMHDW])(?:_ago)?$", val_str)
        if rel_match:
            qty = int(rel_match.group(1))
            unit = rel_match.group(2).lower()
            now = reference_time or datetime.now(timezone.utc).replace(tzinfo=None)
            if unit == "s":
                return now - timedelta(seconds=qty)
            elif unit == "m":
                return now - timedelta(minutes=qty)
            elif unit == "h":
                return now - timedelta(hours=qty)
            elif unit == "d":
                return now - timedelta(days=qty)
            elif unit == "w":
                return now - timedelta(weeks=qty)

        raise ValueError(
            f"Invalid timestamp value: '{val_str}'. Expected ISO datetime or relative format like '24h', '7d', '15m'."
        )

    def _build_filter(self, model, cond: dict, reference_time: Optional[datetime] = None):
        field_name = cond.get("field")
        operator = cond.get("operator")
        value = cond.get("value")

        if not field_name or field_name not in ALLOWED_SEARCH_FIELDS:
            raise ValueError(
                f"Unsupported search field: '{field_name}'. Allowed: {', '.join(sorted(ALLOWED_SEARCH_FIELDS))}"
            )

        # Resolve model column
        if field_name == "payload_content":
            column = PacketLog.raw_payload
        elif hasattr(model, field_name):
            column = getattr(model, field_name)
        else:
            raise ValueError(
                f"Unsupported search field: '{field_name}'. Allowed: {', '.join(sorted(ALLOWED_SEARCH_FIELDS))}"
            )

        # Threat score normalization: 0.0 - 1.0 canonical representation
        if field_name == "threat_score":
            try:
                val_f = float(value)
                if val_f > 1.0:
                    value = val_f / 100.0
                else:
                    value = val_f
            except (ValueError, TypeError):
                pass

        # Timestamp relative parsing and handling
        if field_name == "timestamp":
            if operator == "between":
                if isinstance(value, str) and "," in value:
                    value = [x.strip() for x in value.split(",")]
                if isinstance(value, (list, tuple)) and len(value) == 2:
                    dt1 = self._parse_timestamp_value(value[0], reference_time)
                    dt2 = self._parse_timestamp_value(value[1], reference_time)
                    return column.between(dt1, dt2)
                raise ValueError("Operator 'between' requires a 2-element range.")
            elif operator == "in_list":
                raise ValueError("Operator 'in_list' is not supported for timestamp column.")
            else:
                value = self._parse_timestamp_value(value, reference_time)

        # Standard operator mapping
        if operator == "equals":
            return column == value
        elif operator == "not_equals":
            return column != value
        elif operator == "contains":
            escaped = str(value).replace("%", "\\%").replace("_", "\\_")
            return column.ilike(f"%{escaped}%")
        elif operator == "not_contains":
            escaped = str(value).replace("%", "\\%").replace("_", "\\_")
            # Explicit NULL safety: in SQL three-valued logic, NOT(NULL LIKE pattern) evaluates
            # to NULL (false). Explicitly match rows where column IS NULL or NOT LIKE pattern.
            return or_(column.is_(None), ~column.ilike(f"%{escaped}%"))
        elif operator == "starts_with":
            escaped = str(value).replace("%", "\\%").replace("_", "\\_")
            return column.ilike(f"{escaped}%")
        elif operator == "greater_than":
            return column > value
        elif operator == "less_than":
            return column < value
        elif operator == "greater_than_or_equal":
            return column >= value
        elif operator == "less_than_or_equal":
            return column <= value
        elif operator == "between":
            if isinstance(value, str) and "," in value:
                value = [x.strip() for x in value.split(",")]
            if isinstance(value, (list, tuple)) and len(value) == 2:
                return column.between(value[0], value[1])
            raise ValueError("Operator 'between' requires a 2-element range.")
        elif operator == "in_list":
            if isinstance(value, str):
                val_list = [x.strip() for x in value.split(",") if x.strip()]
            elif isinstance(value, (list, tuple)):
                val_list = list(value)
            else:
                val_list = [value]
            return column.in_(val_list)

        raise ValueError(
            f"Invalid operator '{operator}'. Allowed: {', '.join(sorted(VALID_OPERATORS))}"
        )

    def _format_packet_log(self, log):
        return {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "src_port": log.src_port,
            "dst_port": log.dst_port,
            "protocol": log.protocol,
            "length": log.length,
            "threat_score": log.threat_score,
            "threat_level": log.threat_level,
            "attack_type": log.attack_type,
            "is_malicious": log.is_malicious,
            "payload_content": log.raw_payload or "",
            "confidence": getattr(log, "confidence", 1.0),
            "country": getattr(log, "country", None),
            "city": getattr(log, "city", None),
        }

    def extract_iocs(self, text: str):
        """
        Regex-based deterministic extraction of IOCs from raw payload or log text.
        Queries database IOC table for watchlist status and deduplicates.
        """
        if not text:
            return []

        ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
        url_pattern = r"https?://[^\s<>'\"{}|\\^`]+"
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b"
        md5_pattern = r"\b[a-fA-F0-9]{32}\b"
        sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

        raw_iocs = []

        # IPv4
        for ip in re.findall(ipv4_pattern, text):
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                if ip not in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
                    raw_iocs.append(("IP", ip))

        # IPv6
        for ip6 in re.findall(ipv6_pattern, text):
            if ip6 not in ["::1", "::"]:
                raw_iocs.append(("IPv6", ip6))

        # URLs
        for url in re.findall(url_pattern, text):
            raw_iocs.append(("URL", url))

        # Emails
        for email in re.findall(email_pattern, text):
            raw_iocs.append(("Email", email.lower()))

        # Domains
        for domain in re.findall(domain_pattern, text):
            domain_lower = domain.lower()
            if not domain_lower.endswith(
                (".py", ".js", ".css", ".html", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".json", ".txt")
            ):
                raw_iocs.append(("Domain", domain_lower))

        # Hashes (SHA256 first, then MD5)
        for sha in re.findall(sha256_pattern, text):
            raw_iocs.append(("SHA256", sha.lower()))

        for md5 in re.findall(md5_pattern, text):
            if not any(md5.lower() in sha.lower() for t, sha in raw_iocs if t == "SHA256"):
                raw_iocs.append(("MD5", md5.lower()))

        # Deduplicate preserving order
        seen = set()
        unique_iocs = []
        for ioc_type, val in raw_iocs:
            key = (ioc_type, val)
            if key not in seen:
                seen.add(key)
                unique_iocs.append(key)

        # Query watchlist status from DB
        watchlist_set = set()
        try:
            rows = self.db.query(IOC.value).filter(IOC.is_watchlist == True).all()
            watchlist_set = {r[0] for r in rows}
        except Exception as exc:
            logger.warning("Could not fetch IOC watchlist status: %s", exc)

        return [
            {
                "type": ioc_type,
                "value": val,
                "in_watchlist": val in watchlist_set,
            }
            for ioc_type, val in unique_iocs
        ]

    def get_watchlist(self):
        """
        Retrieve all IOCs marked as watchlist items from the persistent database table.
        """
        iocs = (
            self.db.query(IOC)
            .filter(IOC.is_watchlist == True)
            .order_by(IOC.last_seen.desc())
            .all()
        )
        return [
            {
                "id": ioc.id,
                "type": ioc.type,
                "value": ioc.value,
                "threat_level": ioc.threat_level,
                "description": ioc.description,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            }
            for ioc in iocs
        ]

    def toggle_watchlist(self, ioc_type: str, value: str):
        """
        Persistently toggle an IOC in the database watchlist.
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        ioc = self.db.query(IOC).filter(IOC.type == ioc_type, IOC.value == value).first()
        if ioc:
            ioc.is_watchlist = not ioc.is_watchlist
            ioc.last_seen = now
            self.db.commit()
            self.db.refresh(ioc)
            return {
                "status": "success",
                "in_watchlist": ioc.is_watchlist,
                "value": value,
                "type": ioc_type,
            }
        else:
            new_ioc = IOC(
                type=ioc_type,
                value=value,
                threat_level="Medium",
                is_watchlist=True,
                first_seen=now,
                last_seen=now,
                created_at=now,
            )
            self.db.add(new_ioc)
            self.db.commit()
            self.db.refresh(new_ioc)
            return {
                "status": "success",
                "in_watchlist": True,
                "value": value,
                "type": ioc_type,
            }

    def get_related_events(
        self, ip: str, honeypot_type: str = None, window_minutes: int = 1440
    ):
        """
        Find events related to a specific IP or same honeypot within a time window.
        """
        start_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=window_minutes)

        query = self.db.query(PacketLog).filter(PacketLog.timestamp >= start_time)

        if ip and honeypot_type:
            query = query.filter(
                or_(PacketLog.src_ip == ip, PacketLog.protocol.ilike(honeypot_type))
            )
        elif ip:
            query = query.filter(PacketLog.src_ip == ip)
        elif honeypot_type:
            query = query.filter(PacketLog.protocol.ilike(honeypot_type))

        results = query.order_by(desc(PacketLog.timestamp)).limit(50).all()
        return [self._format_packet_log(log) for log in results]

    def detect_malicious_patterns(self, text: str):
        """
        Detect potential malicious signatures in raw data.
        """
        patterns = {
            "SQL Injection": [r"UNION\s+SELECT", r"OR\s+1=1", r"--;", r"DROP\s+TABLE"],
            "Cross-Site Scripting (XSS)": [
                r"<script",
                r"javascript:",
                r"onerror=",
                r"alert\(",
            ],
            "Directory Traversal": [r"\.\./\.\.", r"etc/passwd", r"windows/win\.ini"],
            "Command Injection": [
                r";\s*cat\b",
                r"\|\s*grep\b",
                r"&&\s*id\b",
                r"\$\(whoami\)",
            ],
        }

        detected = []
        for category, regex_list in patterns.items():
            for regex in regex_list:
                if re.search(regex, text, re.IGNORECASE):
                    detected.append(category)
                    break

        return detected
