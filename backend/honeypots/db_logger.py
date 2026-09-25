"""
Shared Database Logger for Honeypots
Logs honeypot activity directly to the PacketLog table for accurate last_seen tracking.
"""

import os
import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Lazy database availability flag
DB_AVAILABLE = None

import socket

def is_healthcheck(src_ip: str) -> bool:
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
    **kwargs,
):
    """
    Log honeypot activity to the database or ingestion gateway.
    """
    if is_healthcheck(src_ip):
        return False

    # Check if Ingestion Gateway is configured (Phase 2 Durable Architecture)
    gateway_url = os.getenv("INGESTION_GATEWAY_URL")
    if gateway_url:
        try:
            from honeypots.event_dispatcher import default_dispatcher
            return default_dispatcher.dispatch(
                protocol=protocol,
                src_ip=src_ip,
                event_type=event_type,
                length=length,
                is_malicious=is_malicious,
                threat_score=threat_score,
                attack_type=attack_type,
                dst_ip=kwargs.get("dst_ip", "127.0.0.1"),
                src_port=kwargs.get("src_port", 0),
                dst_port=kwargs.get("dst_port", 0),
                threat_level=kwargs.get("threat_level"),
                payload=kwargs.get("payload"),
            )
        except Exception as ge:
            print(f"[DB Logger] Error dispatching to gateway: {ge}")
            return False

    global DB_AVAILABLE
    if DB_AVAILABLE is None:
        try:
            from database import SessionLocal
            from database.models import PacketLog
            from services.geoip_service import geoip_service
            DB_AVAILABLE = True
        except Exception as e:
            DB_AVAILABLE = False

    if not DB_AVAILABLE:
        return False

    try:
        from schemas.event_envelope import generate_uuidv7, compute_canonical_fingerprint
        from database import SessionLocal
        from database.models import PacketLog
        from services.geoip_service import geoip_service
        db = SessionLocal()

        # GeoIP Enrichment
        geo = geoip_service.lookup(src_ip)
        now = datetime.utcnow()
        event_uuid = generate_uuidv7()
        fp = compute_canonical_fingerprint(
            honeypot_id=protocol.lower(),
            event_type=event_type,
            src_ip=src_ip,
            dst_port=0,
            protocol=protocol,
            payload={},
            timestamp_ns=int(now.timestamp() * 1_000_000_000),
        )

        log_entry = PacketLog(
            timestamp=now,
            src_ip=src_ip,
            dst_ip="127.0.0.1",
            protocol=protocol.upper(),  # Ensure uppercase: HTTP, FTP, SMTP, SSH
            length=length,
            is_malicious=is_malicious,
            threat_score=threat_score,
            attack_type=attack_type or event_type.upper(),
            event_id=event_uuid,
            canonical_fingerprint=fp,
            honeypot_id=protocol.lower(),
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
