
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
            # Fetch logs where threat_level is NULL
            # This ensures we process all logs through the new ML pipeline
            logs = db.query(PacketLog).filter(
                PacketLog.threat_level.is_(None)
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
                            src_port=log.src_port or 0,
                            dst_port=log.dst_port or 0,
                            protocol=log.protocol or "UNKNOWN",
                            length=log.length or 0,
                        )
                        result = score_threat(input_data)
                        
                        # 2. Enrich with Threat Intelligence (Proactively)
                        try:
                            import asyncio
                            from services.threat_intel import threat_intel_service
                            # Use asyncio.run to call the async enrichment from the background thread
                            enrichment = asyncio.run(threat_intel_service.enrich_ip(log.src_ip))
                            
                            if isinstance(enrichment, dict) and 'abuse_ipdb' in enrichment:
                                abuse_score = enrichment['abuse_ipdb'].get('abuse_confidence_score', 0)
                                if abuse_score > 50:
                                    # Professional Score Scaling
                                    result.score = min(100, result.score + (abuse_score / 2.5))
                                    result.threat_level = "HIGH" if result.score >= 70 else result.threat_level
                        except Exception as intel_e:
                            logger.error(f"Failed to enrich log {log.id}: {intel_e}")

                        self._cache_score(log.src_ip, result)
                    except Exception as e:
                        logger.error(f"Failed to score log {log.id}: {e}")
                        continue

                # 3. Update DB Record
                log.threat_score = result.score
                log.threat_level = result.threat_level
                log.confidence = result.confidence
                log.attack_type = result.decision
                log.is_malicious = result.threat_level in ["HIGH", "CRITICAL"]
                
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
