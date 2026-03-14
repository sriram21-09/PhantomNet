import time
import logging
import threading
from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session
from database.database import SessionLocal
from database.models import PacketLog
from .alert_manager import alert_manager

logger = logging.getLogger("correlation_engine")


class CorrelationEngine:
    def __init__(self, check_interval: int = 10, window_minutes: int = 5):
        self.check_interval = check_interval
        self.window_minutes = window_minutes
        self._stop_event = threading.Event()
        self.running = False

    def start(self):
        if self.running:
            return
        self.running = True
        self._stop_event.clear()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info("Correlation Engine started.")

    def stop(self):
        self.running = False
        self._stop_event.set()
        if hasattr(self, "thread"):
            self.thread.join(timeout=2)
        logger.info("Correlation Engine stopped.")

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self._correlate_events()
            except Exception as e:
                logger.error(f"Error in correlation loop: {e}")

            time.sleep(self.check_interval)

    def _correlate_events(self):
        db: Session = SessionLocal()
        try:
            time_threshold = datetime.utcnow() - timedelta(minutes=self.window_minutes)

            # 1. Detect Multi-Protocol Attacks (Vertical Scanning)
            # Find IPs that have accessed > 2 different protocols in the last window
            multi_protocol_ips = (
                db.query(
                    PacketLog.src_ip,
                    func.count(func.distinct(PacketLog.protocol)).label("proto_count"),
                )
                .filter(PacketLog.timestamp >= time_threshold)
                .group_by(PacketLog.src_ip)
                .having(func.count(func.distinct(PacketLog.protocol)) > 2)
                .all()
            )

            for ip, count in multi_protocol_ips:
                alert_manager.create_alert(
                    level="CRITICAL",
                    alert_type="CORRELATION",
                    source_ip=ip,
                    description=f"Multi-protocol attack detected: {count} distinct protocols from same IP.",
                    details={
                        "protocols_count": count,
                        "window_minutes": self.window_minutes,
                    },
                )

            # 2. Detect High-Frequency Attacks
            # Find IPs with more than 50 events in the last window
            high_freq_ips = (
                db.query(
                    PacketLog.src_ip, func.count(PacketLog.id).label("event_count")
                )
                .filter(PacketLog.timestamp >= time_threshold)
                .group_by(PacketLog.src_ip)
                .having(func.count(PacketLog.id) > 50)
                .all()
            )

            for ip, count in high_freq_ips:
                alert_manager.create_alert(
                    level="WARNING",
                    alert_type="CORRELATION",
                    source_ip=ip,
                    description=f"High frequency activity: {count} events in {self.window_minutes} minutes.",
                    details={
                        "event_count": count,
                        "window_minutes": self.window_minutes,
                    },
                )

        except Exception as e:
            logger.error(f"Database error in CorrelationEngine: {e}")
        finally:
            db.close()


# Singleton instance
correlation_engine = CorrelationEngine()
