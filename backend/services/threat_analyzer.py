
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
from ml_engine.pattern_detector import AdvancedPatternDetector
from database.database import get_db

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
        self.last_pattern_scan = datetime.now()
        self.pattern_scan_interval = 60 # Run advanced patterns every minute

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
                
                # Check if it's time to run advanced patterns (Distributed Brute Force, Low & Slow)
                if (datetime.now() - self.last_pattern_scan).total_seconds() >= self.pattern_scan_interval:
                    self._process_advanced_patterns()
                    self.last_pattern_scan = datetime.now()
                    
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

    def _process_advanced_patterns(self):
        db: Session = SessionLocal()
        try:
            detector = AdvancedPatternDetector(db)
            report = detector.run_all_checks()
            
            threats_found = False
            if report.get("distributed_brute_force_ssh"):
                logger.warning(f"ADVANCED THREAT DETECTED: Distributed Brute Force: {len(report['distributed_brute_force_ssh'])} targets.")
                threats_found = True
            
            if report.get("low_and_slow_scans"):
                logger.warning(f"ADVANCED THREAT DETECTED: Low and Slow scans from {len(report['low_and_slow_scans'])} sources.")
                threats_found = True
                
            if threats_found:
                try:
                    import asyncio
                    from api.topology import push_topology_event
                    asyncio.run(push_topology_event("ADVANCED_THREAT_DETECTED", report))
                except Exception as ws_e:
                    logger.debug(f"Topology advanced threat sync failed: {ws_e}")

        except Exception as e:
            logger.error(f"Error in _process_advanced_patterns: {e}")
        finally:
            db.close()

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
                        self._cache_score(log.src_ip, result)
                    except Exception as e:
                        logger.error(f"Error processing unscored logs: {e}")
                    
                    # 4. Notify Topology Visualization of new activity
                    try:
                        from api.topology import push_topology_event
                        # Just a heartbeat update for now, telling the UI "something happened"
                        asyncio.run(push_topology_event("TRAFFIC_TICK", {"count": len(logs)})) # Changed unscored_logs to logs
                    except Exception as ws_e:
                        logger.debug(f"Topology sync skipped: {ws_e}")

                    time.sleep(2)

                # 3. Update DB Record
                log.threat_score = result.score
                log.threat_level = result.threat_level
                log.confidence = result.confidence
                log.attack_type = result.decision
                log.is_malicious = result.threat_level in ["HIGH", "CRITICAL"]
                
                # 4. Notify Topology Visualization of Threat
                if log.is_malicious:
                    try:
                        from api.topology import push_topology_event
                        asyncio.run(push_topology_event("THREAT_DETECTED", {
                            "attacker_ip": log.src_ip,
                            "target_service": log.dst_port,
                            "threat_score": result.score,
                            "attack_type": result.decision
                        }))
                    except Exception as ws_e:
                        logger.debug(f"Topology threat sync failed: {ws_e}")

                updated_count += 1

            if updated_count > 0:
                db.commit()
                # Change to DEBUG to avoid terminal spam
                logger.debug(f"Analyzed and updated {updated_count} logs.")

        except Exception as e:
            logger.error(f"Database error: {e}")
            db.rollback()
        finally:
            db.close()

# Singleton instance
threat_analyzer = ThreatAnalyzerService()
