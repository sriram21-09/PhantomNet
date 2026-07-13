"""
Shared Database Logger for Honeypots
Logs honeypot activity directly to the PacketLog table for accurate last_seen tracking.
"""

import os
import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from database import SessionLocal
    from database.models import PacketLog
    from services.geo import GeoService

    DB_AVAILABLE = True
except Exception as e:
    print(f"[DB Logger] Database not available: {e}")
    DB_AVAILABLE = False


import socket

def is_healthcheck(src_ip: str) -> bool:
    if src_ip in ["127.0.0.1", "localhost", "::1"]:
        return True
    try:
        api_ip = socket.gethostbyname("api")
        if src_ip == api_ip:
            return True
    except Exception:
        pass
    return False


def log_to_database(
    protocol: str,
    src_ip: str,
    event_type: str = "activity",
    length: int = 0,
    is_malicious: bool = False,
    threat_score: float = 0.0,
    attack_type: str = None,
):
    """
    Log honeypot activity to the database.
    """
    if not DB_AVAILABLE:
        return False

    if is_healthcheck(src_ip):
        return False

    try:
        db = SessionLocal()

        # GeoIP Enrichment
        geo = GeoService.get_geo_info(src_ip)

        log_entry = PacketLog(
            timestamp=datetime.utcnow(),
            src_ip=src_ip,
            dst_ip="127.0.0.1",
            protocol=protocol.upper(),  # Ensure uppercase: HTTP, FTP, SMTP, SSH
            length=length,
            is_malicious=is_malicious,
            threat_score=threat_score,
            attack_type=attack_type or event_type.upper(),
            country=geo.get("country"),
            city=geo.get("city"),
            latitude=geo.get("lat"),
            longitude=geo.get("lon"),
        )

        db.add(log_entry)
        db.commit()
        db.close()
        return True

    except Exception as e:
        print(f"[DB Logger] Error logging to database: {e}")
        return False


# Convenience functions for each protocol
def log_ssh_activity(src_ip: str, event_type: str = "activity", **kwargs):
    return log_to_database("SSH", src_ip, event_type, **kwargs)


def log_http_activity(src_ip: str, event_type: str = "activity", **kwargs):
    return log_to_database("HTTP", src_ip, event_type, **kwargs)


def log_ftp_activity(src_ip: str, event_type: str = "activity", **kwargs):
    return log_to_database("FTP", src_ip, event_type, **kwargs)


def log_smtp_activity(src_ip: str, event_type: str = "activity", **kwargs):
    return log_to_database("SMTP", src_ip, event_type, **kwargs)


def log_mysql_activity(src_ip: str, event_type: str = "activity", **kwargs):
    return log_to_database("MYSQL", src_ip, event_type, **kwargs)
