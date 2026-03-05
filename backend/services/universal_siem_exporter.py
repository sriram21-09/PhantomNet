import os
import json
import logging
from abc import ABC, abstractmethod
from typing import List, Any, Dict, Optional

# Note: We assume requests and socket are available or handled by specific exporters
import requests
import socket

from database.models import PacketLog, Alert

logger = logging.getLogger("universal_siem_exporter")

# =======================================================================
# Common Converters (from previous siem_exporter logic)
# =======================================================================
CEF_VENDOR = "PhantomNet"
CEF_PRODUCT = "IDS"
CEF_VERSION = "1.0"

SEVERITY_MAP = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
    None: 0,
}

def item_to_json(item: Any, event_type: str) -> Dict[str, Any]:
    if isinstance(item, PacketLog):
        return {
            "event_id": item.id,
            "timestamp": item.timestamp.isoformat() + "Z" if item.timestamp else None,
            "src_ip": item.src_ip,
            "dst_ip": item.dst_ip,
            "src_port": item.src_port,
            "dst_port": item.dst_port,
            "protocol": item.protocol,
            "length": item.length,
            "attack_type": item.attack_type,
            "threat_score": item.threat_score,
            "threat_level": item.threat_level,
            "confidence": item.confidence,
            "is_malicious": item.is_malicious,
            "event": item.event,
            "source": "phantomnet",
            "event_type": "packet_log",
        }
    elif isinstance(item, Alert):
        return {
            "event_id": f"alert-{item.id}",
            "timestamp": item.timestamp.isoformat() + "Z" if item.timestamp else None,
            "src_ip": item.source_ip,
            "alert_level": item.level,
            "alert_type": item.type,
            "description": item.description,
            "details": item.details,
            "is_resolved": item.is_resolved,
            "country": item.country,
            "city": item.city,
            "latitude": item.latitude,
            "longitude": item.longitude,
            "source": "phantomnet",
            "event_type": "alert",
        }
    return {}

def item_to_cef(item: Any, event_type: str) -> str:
    if isinstance(item, PacketLog):
        severity = SEVERITY_MAP.get(item.threat_level, 0)
        sig_id = item.attack_type or "TRAFFIC"
        name = f"{item.protocol or 'UNKNOWN'} event from {item.src_ip}"
        extensions = (
            f"src={item.src_ip} "
            f"dst={item.dst_ip or ''} "
            f"spt={item.src_port or 0} "
            f"dpt={item.dst_port or 0} "
            f"proto={item.protocol or ''} "
            f"cn1={item.threat_score or 0} cn1Label=ThreatScore "
            f"cn2={item.confidence or 0} cn2Label=Confidence "
            f"cs1={item.threat_level or 'NONE'} cs1Label=ThreatLevel "
            f"msg={item.event or ''}"
        )
        return f"CEF:0|{CEF_VENDOR}|{CEF_PRODUCT}|{CEF_VERSION}|{sig_id}|{name}|{severity}|{extensions}"
    
    elif isinstance(item, Alert):
        sev_map = {"CRITICAL": 10, "WARNING": 7, "INFO": 3}
        severity = sev_map.get(item.level, 0)
        sig_id = item.type or "ALERT"
        name = f"Alert: {item.description[:80]}" if item.description else "Alert"
        extensions = (
            f"src={item.source_ip or ''} "
            f"cs1={item.level or ''} cs1Label=AlertLevel "
            f"cs2={item.type or ''} cs2Label=AlertType "
            f"msg={item.description or ''}"
        )
        return f"CEF:0|{CEF_VENDOR}|{CEF_PRODUCT}|{CEF_VERSION}|{sig_id}|{name}|{severity}|{extensions}"
    return ""


# =======================================================================
# Abstract Base Class
# =======================================================================
class SIEMExporter(ABC):
    """
    Abstract base class for all SIEM exporters.
    """
    
    @abstractmethod
    def export_events(self, items: List[Any], event_type: str) -> bool:
        """
        Export a batch of events (PacketLogs or Alerts).
        Returns True if successful, False otherwise.
        """
        pass

# =======================================================================
# ELK (Logstash HTTP) Exporter
# =======================================================================
class ELKExporter(SIEMExporter):
    """
    Ships JSON events to Logstash via HTTP.
    """
    def __init__(self, logstash_url: str):
        self.url = logstash_url
        self.headers = {"Content-Type": "application/json"}

    def export_events(self, items: List[Any], event_type: str) -> bool:
        if not items:
            return True
            
        payload = [item_to_json(item, event_type) for item in items]
        try:
            resp = requests.post(self.url, json=payload, headers=self.headers, timeout=10)
            if resp.status_code in (200, 201, 202):
                logger.info(f"✅ Shipped {len(payload)} events to Logstash")
                return True
            logger.warning(f"⚠️ Logstash returned HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"❌ ELK export failed: {e}")
        return False

# =======================================================================
# CEF Exporter (HTTP via Logstash or similar)
# =======================================================================
class CEFExporter(SIEMExporter):
    """
    Ships CEF string events wrapped in JSON to Logstash or an HTTP endpoint.
    """
    def __init__(self, target_url: str):
        self.url = target_url
        self.headers = {"Content-Type": "application/json"}

    def export_events(self, items: List[Any], event_type: str) -> bool:
        if not items:
            return True
            
        payload = [{"message": item_to_cef(item, event_type)} for item in items]
        try:
            resp = requests.post(self.url, json=payload, headers=self.headers, timeout=10)
            if resp.status_code in (200, 201, 202):
                logger.info(f"✅ Shipped {len(payload)} CEF events")
                return True
            logger.warning(f"⚠️ CEF HTTP endpoint returned {resp.status_code}")
        except Exception as e:
            logger.error(f"❌ CEF export failed: {e}")
        return False

# =======================================================================
# Syslog Exporter (UDP/TCP)
# =======================================================================
class SyslogExporter(SIEMExporter):
    """
    Ships CEF strings over UDP or TCP directly to a Syslog server.
    """
    def __init__(self, host: str, port: int, protocol: str = "UDP"):
        self.host = host
        self.port = port
        self.protocol = protocol.upper()

    def export_events(self, items: List[Any], event_type: str) -> bool:
        if not items:
            return True
            
        try:
            sock_type = socket.SOCK_DGRAM if self.protocol == "UDP" else socket.SOCK_STREAM
            with socket.socket(socket.AF_INET, sock_type) as sock:
                # If TCP, connect first
                if self.protocol == "TCP":
                    sock.settimeout(5.0)
                    sock.connect((self.host, self.port))
                
                for item in items:
                    cef_str = item_to_cef(item, event_type) + "\n"
                    if self.protocol == "UDP":
                        sock.sendto(cef_str.encode("utf-8"), (self.host, self.port))
                    else:
                        sock.sendall(cef_str.encode("utf-8"))
            
            logger.info(f"✅ Shipped {len(items)} events to Syslog ({self.protocol})")
            return True
        except Exception as e:
            logger.error(f"❌ Syslog export failed: {e}")
            return False

# =======================================================================
# Export Factory
# =======================================================================
def get_siem_exporter() -> SIEMExporter:
    """
    Factory method to initialize and return the appropriate SIEMExporter based on env.
    """
    siem_type = os.getenv("SIEM_TYPE", "elk").lower()
    
    if siem_type == "elk" or siem_type == "json":
        logstash_url = os.getenv("LOGSTASH_URL", "http://localhost:5044")
        return ELKExporter(logstash_url)
        
    elif siem_type == "cef":
        # Assumes Logstash or HTTP endpoint accepting {"message": "... CEF string ..."}
        logstash_url = os.getenv("LOGSTASH_URL", "http://localhost:5044")
        return CEFExporter(logstash_url)
        
    elif siem_type == "syslog":
        syslog_host = os.getenv("SYSLOG_HOST", "localhost")
        syslog_port = int(os.getenv("SYSLOG_PORT", "514"))
        syslog_proto = os.getenv("SYSLOG_PROTO", "UDP")
        return SyslogExporter(syslog_host, syslog_port, syslog_proto)
        
    elif siem_type == "splunk":
        # Import dynamically to avoid circular dependencies if SplunkExporter gets complex
        try:
            from services.splunk_exporter import SplunkExporter
            url = os.getenv("SPLUNK_HEC_URL", "http://localhost:8088/services/collector/event")
            token = os.getenv("SPLUNK_HEC_TOKEN", "")
            return SplunkExporter(url, token)
        except ImportError as e:
            logger.error(f"Failed to load Splunk Export Module: {e}")
            # Fallback to ELK if Splunk is missing
            return ELKExporter(os.getenv("LOGSTASH_URL", "http://localhost:5044"))
            
    else:
        logger.warning(f"Unknown SIEM_TYPE '{siem_type}', defaulting to ELK/Logstash JSON.")
        return ELKExporter(os.getenv("LOGSTASH_URL", "http://localhost:5044"))
