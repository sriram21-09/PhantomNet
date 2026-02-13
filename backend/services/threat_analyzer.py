
import time
import logging
import threading
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List, Optional

# Local imports
from database.database import SessionLocal
from database.models import PacketLog
from ml.threat_scoring_service import score_threat
from schemas.threat_schema import ThreatInput

# Configure logging
logger = logging.getLogger("threat_analyzer")
logger.setLevel(logging.INFO)

class ThreatAnalyzerService:
    def __init__(self, poll_interval: int = 5):
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._cache = {}  # Simple Dict Cache [IP -> {score, level, timestamp}]
        self._cache_ttl = 60  # Seconds
        self.running = False

    def start(self):
        """Starts the background analysis loop."""
        if self.running:
            return
        self.running = True
        self._stop_event.clear()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info("Threat Analyzer Service started.")

    def stop(self):
        """Stops the analysis loop."""
        self.running = False
        self._stop_event.set()
        if hasattr(self, 'thread'):
            self.thread.join(timeout=2)
        logger.info("Threat Analyzer Service stopped.")

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self._process_unscored_logs()
            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")
            
            time.sleep(self.poll_interval)

    def _get_cached_score(self, ip: str):
        """Returns cached score if valid."""
        if ip in self._cache:
            data = self._cache[ip]
            if datetime.now() - data['timestamp'] < timedelta(seconds=self._cache_ttl):
                return data
            else:
                del self._cache[ip]
        return None

    def _cache_score(self, ip: str, result):
        """Caches the scoring result."""
        self._cache[ip] = {
            'timestamp': datetime.now(),
            'result': result
        }

    def _process_unscored_logs(self):
        db: Session = SessionLocal()
        try:
            # Fetch logs where threat_score is NULL
            # Limit to 50 to avoid blocking
            logs = db.query(PacketLog).filter(
                PacketLog.threat_score.is_(None)
            ).order_by(PacketLog.timestamp.desc()).limit(50).all()

            updated_count = 0
            for log in logs:
                # 1. Check Cache
                # ... (skipping cache logic for brevity in replace block if possible, but context requires full block)
                cached = self._get_cached_score(log.src_ip)
                if cached:
                    result = cached['result']
                else:
                    try:
                        input_data = ThreatInput(
                            src_ip=log.src_ip,
                            dst_ip=log.dst_ip or "127.0.0.1",
                            src_port=0,
                            dst_port=0,
                            protocol=log.protocol or "UNKNOWN",
                            length=log.length or 0,
                        )
                        result = score_threat(input_data)
                        self._cache_score(log.src_ip, result)
                    except Exception as e:
                        logger.error(f"Failed to score log {log.id}: {e}")
                        continue

                # 3. Update DB Record
                log.threat_score = result.get("score", 0.0)
                # log.threat_level = result.threat_level  <-- COLUMN DOES NOT EXIST
                # log.anomaly_score = result.confidence   <-- COLUMN DOES NOT EXIST
                log.attack_type = result.get("decision", "BENIGN")
                log.is_malicious = result.get("threat_level", "LOW") in ["HIGH", "CRITICAL"]
                
                updated_count += 1

            if updated_count > 0:
                db.commit()
                logger.info(f"Analyzed and updated {updated_count} logs.")

        except Exception as e:
            logger.error(f"Database error: {e}")
            db.rollback()
        finally:
            db.close()

# Singleton instance
threat_analyzer = ThreatAnalyzerService()
