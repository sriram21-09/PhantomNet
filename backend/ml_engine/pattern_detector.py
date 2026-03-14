from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from typing import List, Dict, Any

from database.models import PacketLog
from database.database import SessionLocal
import logging

logger = logging.getLogger(__name__)


class AdvancedPatternDetector:
    """
    Analyzes historical packet logs to detect complex, multi-stage,
    or covert threats that evade single-packet anomaly detection.
    """

    def __init__(self, db: Session = None):
        self.db = db if db else SessionLocal()

    def detect_distributed_brute_force(
        self,
        time_window_mins: int = 15,
        target_port: int = 2222,
        min_sources: int = 3,
        min_attempts: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Detects multiple distinct IP addresses targeting the same destination port
        with high frequency (botnet behavior).
        """
        since = datetime.utcnow() - timedelta(minutes=time_window_mins)

        # Find destination IPs and Ports that have multiple distinct sources hitting them
        try:
            results = (
                self.db.query(
                    PacketLog.dst_ip,
                    PacketLog.dst_port,
                    func.count(func.distinct(PacketLog.src_ip)).label(
                        "distinct_sources"
                    ),
                    func.count(PacketLog.id).label("total_attempts"),
                )
                .filter(PacketLog.timestamp >= since, PacketLog.dst_port == target_port)
                .group_by(PacketLog.dst_ip, PacketLog.dst_port)
                .having(
                    (func.count(func.distinct(PacketLog.src_ip)) >= min_sources)
                    & (func.count(PacketLog.id) >= min_attempts)
                )
                .all()
            )

            return [
                {
                    "target_ip": r.dst_ip,
                    "target_port": r.dst_port,
                    "distinct_attacker_ips": r.distinct_sources,
                    "total_attempts": r.total_attempts,
                    "pattern": "Distributed Brute Force",
                }
                for r in results
            ]
        except Exception as e:
            logger.error(f"Error detecting distributed brute force: {e}")
            return []

    def detect_low_and_slow_scan(
        self,
        time_window_hours: int = 24,
        min_ports: int = 50,
        max_rate_per_min: float = 2.0,
    ) -> List[Dict[str, Any]]:
        """
        Detects an IP address that scans many ports over a long period,
        evading standard threshold detection.
        """
        since = datetime.utcnow() - timedelta(hours=time_window_hours)

        try:
            # Get sources that hit many distinct ports over the day
            results = (
                self.db.query(
                    PacketLog.src_ip,
                    func.count(func.distinct(PacketLog.dst_port)).label(
                        "distinct_ports"
                    ),
                    func.count(PacketLog.id).label("total_events"),
                )
                .filter(PacketLog.timestamp >= since)
                .group_by(PacketLog.src_ip)
                .having(func.count(func.distinct(PacketLog.dst_port)) >= min_ports)
                .all()
            )

            suspects = []
            for r in results:
                # Calculate rate: events / minutes in window
                rate = r.total_events / (time_window_hours * 60)
                if rate <= max_rate_per_min:  # It's slow
                    suspects.append(
                        {
                            "attacker_ip": r.src_ip,
                            "ports_scanned": r.distinct_ports,
                            "total_events": r.total_events,
                            "rate_per_minute": round(rate, 2),
                            "pattern": "Low and Slow Scan",
                        }
                    )
            return suspects
        except Exception as e:
            logger.error(f"Error detecting low and slow scans: {e}")
            return []

    def run_all_checks(self) -> Dict[str, Any]:
        """Runs all advanced pattern checks and returns a consolidated report."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "distributed_brute_force_ssh": self.detect_distributed_brute_force(
                target_port=2222
            ),
            "low_and_slow_scans": self.detect_low_and_slow_scan(),
        }

    def close(self):
        self.db.close()
