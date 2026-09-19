"""
backend/services/retention_service.py
-------------------------------------
Production Tiered Data Retention Engine (GOV-03)

Enforces data lifecycle policies across all PhantomNet data stores:
  - Packet Logs (default 30 days)
  - Raw Events (default 30 days)
  - Security Alerts (default 90 days)
  - Traffic Stats (default 14 days)
  - PCAP Captures (default 14 days, cleans disk files & DB records)
  - Audit Logs (default 365 days, with immutability safeguard)

Zero Lock Contention Architecture:
  - Executes bounded chunk deletions (batch_size=500 by default)
  - Commits after each chunk to avoid long-running locks or replication lag
  - Preserves platform throughput while background purging runs
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
import os
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from database.models import (
    PacketLog,
    Event,
    Alert,
    TrafficStats,
    PcapCapture,
    AuditLog,
)
try:
    from services.audit_service import audit_log
except ImportError:
    from backend.services.audit_service import audit_log

logger = logging.getLogger("PhantomNet-Retention")


@dataclass
class RetentionConfig:
    packet_logs_days: int = int(os.getenv("RETENTION_PACKET_LOGS_DAYS", "30"))
    events_days: int = int(os.getenv("RETENTION_EVENTS_DAYS", "30"))
    alerts_days: int = int(os.getenv("RETENTION_ALERTS_DAYS", "90"))
    traffic_stats_days: int = int(os.getenv("RETENTION_TRAFFIC_STATS_DAYS", "14"))
    pcaps_days: int = int(os.getenv("RETENTION_PCAPS_DAYS", "14"))
    audit_logs_days: int = int(os.getenv("RETENTION_AUDIT_LOGS_DAYS", "365"))
    audit_log_immutable: bool = os.getenv("AUDIT_LOG_IMMUTABLE", "true").lower() == "true"
    batch_size: int = int(os.getenv("RETENTION_BATCH_SIZE", "500"))


class TieredRetentionEngine:
    """
    Manages data pruning with chunked transactions to prevent database lock contention.
    """

    def __init__(self, config: Optional[RetentionConfig] = None):
        self.config = config or RetentionConfig()

    def purge_model_in_batches(
        self,
        db: Session,
        model_class: Any,
        cutoff: datetime,
        timestamp_col_name: str = "timestamp",
        dry_run: bool = False,
    ) -> int:
        """
        Purges rows older than cutoff in batches of size self.config.batch_size.
        """
        ts_attr = getattr(model_class, timestamp_col_name, None)
        if ts_attr is None:
            raise ValueError(f"Model {model_class} lacks timestamp column '{timestamp_col_name}'")

        if dry_run:
            count = db.query(model_class).filter(ts_attr < cutoff).count()
            return count

        total_purged = 0
        batch_size = max(1, self.config.batch_size)

        while True:
            # Query only IDs to minimize memory and row locking
            expired_rows = (
                db.query(model_class.id)
                .filter(ts_attr < cutoff)
                .limit(batch_size)
                .all()
            )
            if not expired_rows:
                break

            expired_ids = [r[0] for r in expired_rows]
            db.query(model_class).filter(model_class.id.in_(expired_ids)).delete(
                synchronize_session=False
            )
            db.commit()

            total_purged += len(expired_ids)
            logger.debug(
                "Pruned batch of %d records from %s (total: %d)",
                len(expired_ids),
                model_class.__tablename__,
                total_purged,
            )

        return total_purged

    def purge_pcaps(self, db: Session, cutoff: datetime, dry_run: bool = False) -> int:
        """
        Purges expired PCAPs from disk files and database records.
        """
        if dry_run:
            return db.query(PcapCapture).filter(PcapCapture.created_at < cutoff).count()

        total_purged = 0
        batch_size = max(1, self.config.batch_size)

        while True:
            records = (
                db.query(PcapCapture)
                .filter(PcapCapture.created_at < cutoff)
                .limit(batch_size)
                .all()
            )
            if not records:
                break

            for rec in records:
                if rec.file_path and os.path.exists(rec.file_path):
                    try:
                        os.remove(rec.file_path)
                    except OSError as e:
                        logger.warning("Failed to remove PCAP file %s: %s", rec.file_path, e)
                db.delete(rec)

            db.commit()
            total_purged += len(records)

        return total_purged

    def run_retention_cycle(
        self,
        db: Session,
        dry_run: bool = False,
        actor: str = "system_retention_service",
    ) -> Dict[str, Any]:
        """
        Executes a complete tiered retention cycle across all configured tables.
        """
        now = datetime.utcnow()
        results: Dict[str, Any] = {
            "timestamp": now.isoformat(),
            "dry_run": dry_run,
            "purged": {},
            "policies": {
                "packet_logs_days": self.config.packet_logs_days,
                "events_days": self.config.events_days,
                "alerts_days": self.config.alerts_days,
                "traffic_stats_days": self.config.traffic_stats_days,
                "pcaps_days": self.config.pcaps_days,
                "audit_logs_days": self.config.audit_logs_days,
                "audit_log_immutable": self.config.audit_log_immutable,
            },
        }

        # 1. Packet Logs
        pl_cutoff = now - timedelta(days=self.config.packet_logs_days)
        results["purged"]["packet_logs"] = self.purge_model_in_batches(
            db, PacketLog, pl_cutoff, timestamp_col_name="timestamp", dry_run=dry_run
        )

        # 2. Raw Events
        ev_cutoff = now - timedelta(days=self.config.events_days)
        results["purged"]["events"] = self.purge_model_in_batches(
            db, Event, ev_cutoff, timestamp_col_name="timestamp", dry_run=dry_run
        )

        # 3. Alerts
        al_cutoff = now - timedelta(days=self.config.alerts_days)
        results["purged"]["alerts"] = self.purge_model_in_batches(
            db, Alert, al_cutoff, timestamp_col_name="timestamp", dry_run=dry_run
        )

        # 4. Traffic Stats
        ts_cutoff = now - timedelta(days=self.config.traffic_stats_days)
        results["purged"]["traffic_stats"] = self.purge_model_in_batches(
            db, TrafficStats, ts_cutoff, timestamp_col_name="timestamp", dry_run=dry_run
        )

        # 5. PCAP Captures
        pcap_cutoff = now - timedelta(days=self.config.pcaps_days)
        results["purged"]["pcap_captures"] = self.purge_pcaps(
            db, pcap_cutoff, dry_run=dry_run
        )

        # 6. Audit Logs (Protected by compliance immutability guard)
        if self.config.audit_log_immutable:
            results["purged"]["audit_logs"] = 0
            results["audit_logs_status"] = "immutable_retention_enforced"
        else:
            audit_cutoff = now - timedelta(days=self.config.audit_logs_days)
            results["purged"]["audit_logs"] = self.purge_model_in_batches(
                db, AuditLog, audit_cutoff, timestamp_col_name="timestamp", dry_run=dry_run
            )
            results["audit_logs_status"] = "purged_past_retention_window"

        total_records = sum(results["purged"].values())
        results["total_purged"] = total_records

        # Record cryptographic audit entry for retention action if not dry run
        if not dry_run and total_records > 0:
            try:
                audit_log(
                    actor=actor,
                    action="DATA_RETENTION_PURGE",
                    result="success",
                    target="database_tables",
                    reason=f"Periodic data lifecycle purge completed: {total_records} records removed",
                    details=results["purged"],
                    db=db,
                )
            except Exception as e:
                logger.error("Failed to write audit entry for retention cycle: %s", e)

        logger.info(
            "✅ Retention cycle complete (dry_run=%s). Pruned %d total records.",
            dry_run,
            total_records,
        )
        return results


retention_engine = TieredRetentionEngine()
