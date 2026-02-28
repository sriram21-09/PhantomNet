import time
import logging
import threading
from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session
from database.database import SessionLocal
from database.models import PacketLog
from .alert_manager import alert_manager

logger = logging.getLogger("baseline_monitor")

class BaselineMonitor:
    def __init__(self, check_interval: int = 60, window_minutes: int = 60):
        """
        :param check_interval: How often to check for spikes (seconds)
        :param window_minutes: Window size to calculate baseline (minutes)
        """
        self.check_interval = check_interval
        self.window_minutes = window_minutes
        self._stop_event = threading.Event()
        self.running = False
        
        # Simple state for baseline (in a real app, this might be persistent)
        self.average_events_per_minute = 0.0
        self.baseline_calculated = False

    def start(self):
        if self.running:
            return
        self.running = True
        self._stop_event.clear()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info("Baseline Monitor started.")

    def stop(self):
        self.running = False
        self._stop_event.set()
        if hasattr(self, 'thread'):
            self.thread.join(timeout=2)
        logger.info("Baseline Monitor stopped.")

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self._analyze_baseline()
            except Exception as e:
                logger.error(f"Error in baseline monitor loop: {e}")
            
            time.sleep(self.check_interval)

    def _analyze_baseline(self):
        db: Session = SessionLocal()
        try:
            now = datetime.utcnow()
            
            # 1. Calculate current activity (last 1 minute)
            last_min_start = now - timedelta(minutes=1)
            current_activity = db.query(func.count(PacketLog.id)).filter(
                PacketLog.timestamp >= last_min_start
            ).scalar() or 0

            # 2. Calculate baseline if not established
            if not self.baseline_calculated:
                window_start = now - timedelta(minutes=self.window_minutes)
                total_in_window = db.query(func.count(PacketLog.id)).filter(
                    PacketLog.timestamp >= window_start
                ).scalar() or 0
                
                self.average_events_per_minute = total_in_window / self.window_minutes
                self.baseline_calculated = True
                logger.info(f"Established baseline: {self.average_events_per_minute:.2f} events/min")

            # 3. Check for Anomalies (Spikes)
            # Threshold: 5x baseline AND at least 20 events (to avoid noise at low volumes)
            threshold = max(self.average_events_per_minute * 5, 20)
            
            if current_activity > threshold:
                alert_manager.create_alert(
                    level="CRITICAL" if current_activity > threshold * 2 else "WARNING",
                    alert_type="BASELINE",
                    description=f"Traffic spike detected: {current_activity} events/min (Baseline: {self.average_events_per_minute:.2f})",
                    details={
                        "current_activity": current_activity,
                        "baseline": self.average_events_per_minute,
                        "threshold": threshold
                    }
                )
                logger.warning(f"Traffic spike detected: {current_activity} (Baseline: {self.average_events_per_minute:.2f})")

            # 4. Slowly update baseline (Drift compensation)
            # 90% old baseline, 10% current activity
            # Only update if current activity isn't a massive spike to avoid poisoning the baseline
            if current_activity < threshold * 2:
                self.average_events_per_minute = (self.average_events_per_minute * 0.95) + (current_activity * 0.05)

        except Exception as e:
            logger.error(f"Database error in BaselineMonitor: {e}")
        finally:
            db.close()

# Singleton instance
baseline_monitor = BaselineMonitor()
