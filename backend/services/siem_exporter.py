"""
PhantomNet SIEM Exporter Service
================================
Automated log export service for ELK Stack integration.
Queries security events from PostgreSQL, transforms them into
SIEM-compatible formats (CEF/JSON), and ships to Logstash via HTTP.

Features:
- Scheduled export every 60 seconds via APScheduler
- Batch processing (1000 events per batch)
- Retry logic with exponential backoff
- CEF and JSON output formats
- Watermark-based cursor to avoid re-exporting
"""

import os
import json
import time
import logging
import requests
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session
from sqlalchemy import and_

from database.database import SessionLocal
from database.models import PacketLog, Alert

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("siem_exporter")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOGSTASH_URL = os.getenv("LOGSTASH_URL", "http://localhost:5044")
EXPORT_INTERVAL_SECONDS = int(os.getenv("SIEM_EXPORT_INTERVAL", "60"))
BATCH_SIZE = int(os.getenv("SIEM_BATCH_SIZE", "1000"))
OUTPUT_FORMAT = os.getenv("SIEM_OUTPUT_FORMAT", "json")  # "json" or "cef"
MAX_RETRIES = int(os.getenv("SIEM_MAX_RETRIES", "5"))
RETRY_BASE_DELAY = float(os.getenv("SIEM_RETRY_BASE_DELAY", "2.0"))

# CEF constants
CEF_VENDOR = "PhantomNet"
CEF_PRODUCT = "IDS"
CEF_VERSION = "1.0"

# Threat-level → CEF severity mapping
SEVERITY_MAP = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
    None: 0,
}


# ═══════════════════════════════════════════════════════════════════════════
# Format Transformers
# ═══════════════════════════════════════════════════════════════════════════


def _packet_log_to_json(log: PacketLog) -> Dict[str, Any]:
    """
    Transform a PacketLog ORM row into a SIEM-compatible JSON dict.
    """
    return {
        "event_id": log.id,
        "timestamp": log.timestamp.isoformat() + "Z" if log.timestamp else None,
        "src_ip": log.src_ip,
        "dst_ip": log.dst_ip,
        "src_port": log.src_port,
        "dst_port": log.dst_port,
        "protocol": log.protocol,
        "length": log.length,
        "attack_type": log.attack_type,
        "threat_score": log.threat_score,
        "threat_level": log.threat_level,
        "confidence": log.confidence,
        "is_malicious": log.is_malicious,
        "event": log.event,
        "source": "phantomnet",
        "event_type": "packet_log",
    }


def _packet_log_to_cef(log: PacketLog) -> str:
    """
    Transform a PacketLog ORM row into a CEF-formatted string.

    CEF:Version|Device Vendor|Device Product|Device Version|
        Signature ID|Name|Severity|Extension
    """
    severity = SEVERITY_MAP.get(log.threat_level, 0)
    sig_id = log.attack_type or "TRAFFIC"
    name = f"{log.protocol or 'UNKNOWN'} event from {log.src_ip}"

    extensions = (
        f"src={log.src_ip} "
        f"dst={log.dst_ip or ''} "
        f"spt={log.src_port or 0} "
        f"dpt={log.dst_port or 0} "
        f"proto={log.protocol or ''} "
        f"cn1={log.threat_score or 0} cn1Label=ThreatScore "
        f"cn2={log.confidence or 0} cn2Label=Confidence "
        f"cs1={log.threat_level or 'NONE'} cs1Label=ThreatLevel "
        f"msg={log.event or ''}"
    )

    return (
        f"CEF:0|{CEF_VENDOR}|{CEF_PRODUCT}|{CEF_VERSION}"
        f"|{sig_id}|{name}|{severity}|{extensions}"
    )


def _alert_to_json(alert: Alert) -> Dict[str, Any]:
    """
    Transform an Alert ORM row into a SIEM-compatible JSON dict.
    """
    return {
        "event_id": f"alert-{alert.id}",
        "timestamp": alert.timestamp.isoformat() + "Z" if alert.timestamp else None,
        "src_ip": alert.source_ip,
        "alert_level": alert.level,
        "alert_type": alert.type,
        "description": alert.description,
        "details": alert.details,
        "is_resolved": alert.is_resolved,
        "country": alert.country,
        "city": alert.city,
        "latitude": alert.latitude,
        "longitude": alert.longitude,
        "source": "phantomnet",
        "event_type": "alert",
    }


def _alert_to_cef(alert: Alert) -> str:
    """
    Transform an Alert ORM row into a CEF-formatted string.
    """
    sev_map = {"CRITICAL": 10, "WARNING": 7, "INFO": 3}
    severity = sev_map.get(alert.level, 0)
    sig_id = alert.type or "ALERT"
    name = f"Alert: {alert.description[:80]}" if alert.description else "Alert"

    extensions = (
        f"src={alert.source_ip or ''} "
        f"cs1={alert.level or ''} cs1Label=AlertLevel "
        f"cs2={alert.type or ''} cs2Label=AlertType "
        f"msg={alert.description or ''}"
    )

    return (
        f"CEF:0|{CEF_VENDOR}|{CEF_PRODUCT}|{CEF_VERSION}"
        f"|{sig_id}|{name}|{severity}|{extensions}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# HTTP Shipping with Retry
# ═══════════════════════════════════════════════════════════════════════════


def _ship_to_logstash(
    payload: List[Any],
    output_format: str = "json",
    url: str = LOGSTASH_URL,
) -> bool:
    """
    (Deprecated) Left here just in case, but new SIEM export is handled via
    Universal SIEM Exporter in backend/services/universal_siem_exporter.py
    """
    if not payload:
        return True

    headers = {"Content-Type": "application/json"}

    # Prepare body depending on format
    if output_format == "cef":
        # Wrap CEF strings into JSON envelope for HTTP transport
        body = json.dumps([{"message": line} for line in payload])
    else:
        body = json.dumps(payload)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(url, data=body, headers=headers, timeout=30)
            if resp.status_code in (200, 201, 202):
                logger.info(
                    f"✅ Shipped batch of {len(payload)} events to Logstash "
                    f"(attempt {attempt})"
                )
                return True

            logger.warning(
                f"⚠️ Logstash returned HTTP {resp.status_code} "
                f"(attempt {attempt}/{MAX_RETRIES})"
            )

        except requests.exceptions.ConnectionError:
            logger.warning(
                f"⚠️ Connection refused to {url} " f"(attempt {attempt}/{MAX_RETRIES})"
            )
        except requests.exceptions.Timeout:
            logger.warning(
                f"⏱️ Request to Logstash timed out "
                f"(attempt {attempt}/{MAX_RETRIES})"
            )
        except Exception as e:
            logger.error(
                f"❌ Unexpected error shipping to Logstash: {e} "
                f"(attempt {attempt}/{MAX_RETRIES})"
            )

        if attempt < MAX_RETRIES:
            delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
            logger.info(f"⏳ Retrying in {delay:.1f}s...")
            time.sleep(delay)

    logger.error(
        f"🔥 Failed to ship batch after {MAX_RETRIES} attempts — "
        f"{len(payload)} events dropped"
    )
    return False


# ═══════════════════════════════════════════════════════════════════════════
# SIEM Exporter Service
# ═══════════════════════════════════════════════════════════════════════════


class SIEMExporterService:
    """
    Background service that periodically exports PhantomNet security events
    to an ELK Stack (via Logstash HTTP input).

    Usage:
        from services.siem_exporter import siem_exporter
        siem_exporter.start()   # begin scheduled exports
        siem_exporter.stop()    # graceful shutdown
    """

    def __init__(
        self,
        interval: int = EXPORT_INTERVAL_SECONDS,
        batch_size: int = BATCH_SIZE,
    ):
        self.interval = interval
        self.batch_size = batch_size

        from services.universal_siem_exporter import get_siem_exporter

        self.exporter = get_siem_exporter()
        self.logstash_url = "universal_siem"
        self.output_format = os.getenv("SIEM_TYPE", "elk")

        # Watermarks — track last exported IDs to avoid duplicates
        self._last_packet_id: int = 0
        self._last_alert_id: int = 0

        # Scheduler handle
        self._scheduler = None
        self.running = False

        # Statistics
        self.total_exported: int = 0
        self.total_failed: int = 0
        self.last_export_time: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start the scheduled export loop."""
        if self.running:
            logger.warning("SIEM Exporter already running.")
            return

        try:
            from apscheduler.schedulers.background import BackgroundScheduler

            self._scheduler = BackgroundScheduler(daemon=True)
            self._scheduler.add_job(
                self._export_cycle,
                "interval",
                seconds=self.interval,
                id="siem_export_job",
                replace_existing=True,
                max_instances=1,
            )
            self._scheduler.start()
            self.running = True
            logger.info(
                f"🚀 SIEM Exporter started — exporting every {self.interval}s "
                f"to {self.logstash_url} in {self.output_format.upper()} format"
            )
        except ImportError:
            logger.error(
                "❌ APScheduler not installed. " "Install with: pip install apscheduler"
            )
        except Exception as e:
            logger.error(f"❌ Failed to start SIEM Exporter: {e}")

    def stop(self):
        """Gracefully stop the exporter."""
        if self._scheduler:
            self._scheduler.shutdown(wait=False)
        self.running = False
        logger.info(
            f"🛑 SIEM Exporter stopped. "
            f"Total exported: {self.total_exported} | "
            f"Total failed: {self.total_failed}"
        )

    def status(self) -> Dict[str, Any]:
        """Return current exporter status for the management API."""
        return {
            "running": self.running,
            "output_format": self.output_format,
            "logstash_url": self.logstash_url,
            "interval_seconds": self.interval,
            "batch_size": self.batch_size,
            "total_exported": self.total_exported,
            "total_failed": self.total_failed,
            "last_export_time": (
                self.last_export_time.isoformat() if self.last_export_time else None
            ),
            "last_packet_id": self._last_packet_id,
            "last_alert_id": self._last_alert_id,
        }

    # ------------------------------------------------------------------
    # Core Export Cycle
    # ------------------------------------------------------------------

    def _export_cycle(self):
        """
        Single export cycle: query new events → transform → ship.
        Called by the scheduler at each interval.
        """
        logger.debug("SIEM export cycle started")
        db: Session = SessionLocal()

        try:
            # --- Export PacketLogs ---
            exported = self._export_packet_logs(db)

            # --- Export Alerts ---
            exported += self._export_alerts(db)

            if exported > 0:
                self.total_exported += exported
                self.last_export_time = datetime.now(timezone.utc)
                logger.info(
                    f"📦 Export cycle complete — {exported} events shipped "
                    f"(total: {self.total_exported})"
                )
            else:
                logger.debug("No new events to export.")

        except Exception as e:
            logger.error(f"❌ Export cycle failed: {e}")
        finally:
            db.close()

    def _export_packet_logs(self, db: Session) -> int:
        """Query and export new PacketLog rows in batches."""
        total = 0
        while True:
            logs = (
                db.query(PacketLog)
                .filter(PacketLog.id > self._last_packet_id)
                .order_by(PacketLog.id.asc())
                .limit(self.batch_size)
                .all()
            )
            if not logs:
                break

            # Ship using the abstract SIEM exporter
            if self.exporter.export_events(logs, "packet_log"):
                self._last_packet_id = logs[-1].id
                total += len(logs)
            else:
                self.total_failed += len(logs)
                break  # stop batching on failure to avoid data gaps

        return total

    def _export_alerts(self, db: Session) -> int:
        """Query and export new Alert rows in batches."""
        total = 0
        while True:
            alerts = (
                db.query(Alert)
                .filter(Alert.id > self._last_alert_id)
                .order_by(Alert.id.asc())
                .limit(self.batch_size)
                .all()
            )
            if not alerts:
                break

            # Ship using abstract exporter
            if self.exporter.export_events(alerts, "alert"):
                self._last_alert_id = alerts[-1].id
                total += len(alerts)
            else:
                self.total_failed += len(alerts)
                break

        return total

    # ------------------------------------------------------------------
    # Manual / On-Demand Export
    # ------------------------------------------------------------------

    def export_now(self) -> Dict[str, Any]:
        """Trigger an immediate export cycle (callable from API)."""
        logger.info("🔄 Manual export triggered")
        self._export_cycle()
        return self.status()


# ═══════════════════════════════════════════════════════════════════════════
# Singleton
# ═══════════════════════════════════════════════════════════════════════════
siem_exporter = SIEMExporterService()
