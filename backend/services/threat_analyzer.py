
import time
import logging
import threading
import numpy as np
import os
import pickle
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

# Automated Response
from services.response_executor import response_executor

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
        
        self._sequence_buffers = {} # IP -> [buffer of up to 50 feature vectors]
        self._load_lstm()
        
    def _load_lstm(self):
        self.lstm_model = None
        self.lstm_scaler = None
        self.lstm_feature_cols = []
        self.is_mock_lstm = False
        
        pkl_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ml_models', 'lstm_training_data.pkl'))
        if os.path.exists(pkl_path):
            try:
                with open(pkl_path, 'rb') as f:
                    data = pickle.load(f)
                    self.lstm_scaler = data.get('scaler')
                    self.lstm_feature_cols = data.get('feature_cols', [])
            except Exception as e:
                logger.error(f"Failed to load LSTM scaler: {e}")

        h5_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ml_models', 'lstm_attack_predictor.h5'))
        try:
            from tensorflow.keras.models import load_model
            if os.path.exists(h5_path):
                self.lstm_model = load_model(h5_path)
                logger.info("LSTM Model loaded successfully.")
        except Exception as e:
            logger.debug(f"Could not load Keras LSTM model ({e}). Looking for mock fallback.")
            mock_path = h5_path + ".mock.pkl"
            if os.path.exists(mock_path):
                with open(mock_path, 'rb') as f:
                    self.lstm_model = pickle.load(f)
                    self.is_mock_lstm = True
                    logger.info("Loaded Mock LSTM Model for sequence evaluation.")

    def _compute_lstm_score(self, ip: str, log: PacketLog) -> float:
        if not self.lstm_model or not self.lstm_feature_cols:
            return 0.0

        if ip not in self._sequence_buffers:
            self._sequence_buffers[ip] = []
            
        # Fast mock feature approximation
        vec = [0.0] * len(self.lstm_feature_cols)
        self._sequence_buffers[ip].append(vec)
        
        if len(self._sequence_buffers[ip]) > 50:
            self._sequence_buffers[ip] = self._sequence_buffers[ip][-50:]
            
        if len(self._sequence_buffers[ip]) == 50:
            seq = np.array([self._sequence_buffers[ip]]) # shape (1, 50, num_features)
            try:
                if self.is_mock_lstm:
                    seq_flat = seq.reshape(1, -1)
                    probs = self.lstm_model.predict_proba(seq_flat)[0]
                else:
                    probs = self.lstm_model.predict(seq, verbose=0)[0]
                    
                # [LOW(0), MEDIUM(1), HIGH(2)] - weighted threat proxy
                return float(probs[2] * 0.95 + probs[1] * 0.6 + probs[0] * 0.1)
            except Exception as e:
                logger.debug(f"LSTM Prediction error: {e}")
                
        return 0.0

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
            logs = db.query(PacketLog).filter(
                PacketLog.threat_level.is_(None)
            ).order_by(PacketLog.timestamp.desc()).limit(50).all()

            updated_count = 0
            for log in logs:
                cached = self._get_cached_score(log.src_ip)
                if cached:
                    result = cached['result']
                else:
                    try:
                        start_time = time.time()
                        input_data = ThreatInput(
                            src_ip=log.src_ip,
                            dst_ip=log.dst_ip or "127.0.0.1",
                            src_port=log.src_port or 0,
                            dst_port=log.dst_port or 0,
                            protocol=log.protocol or "UNKNOWN",
                            length=log.length or 0,
                        )
                        result = score_threat(input_data)
                        
                        # Apply LSTM sequence ensemble
                        lstm_score = self._compute_lstm_score(log.src_ip, log)
                        
                        # Only apply ensemble if buffer is full (lstm_score > 0)
                        if lstm_score > 0:
                            # 60% RF, 40% LSTM
                            combined_score = (result.score * 0.6) + (lstm_score * 0.4)
                            result.score = combined_score
                            
                            if combined_score >= 0.8:
                                result.threat_level = "CRITICAL"
                            elif combined_score >= 0.6:
                                result.threat_level = "HIGH"
                            elif combined_score >= 0.4:
                                result.threat_level = "MEDIUM"
                            else:
                                result.threat_level = "LOW"
                                
                        inf_time_ms = (time.time() - start_time) * 1000
                        if inf_time_ms > 100:
                            logger.warning(f"Inference time exceeded target! {inf_time_ms:.2f}ms")
                            
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

                # Update DB Record
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

                # Trigger automated response for HIGH/CRITICAL threats
                if result.threat_level in ["HIGH", "CRITICAL"]:
                    try:
                        response_executor.execute(
                            ip=log.src_ip,
                            threat_score=result.score * 100,
                            threat_level=result.threat_level,
                            protocol=log.protocol or "UNKNOWN",
                            details=f"Auto-detected: {result.decision}"
                        )
                    except Exception as e:
                        logger.error(f"Response execution failed for {log.src_ip}: {e}")

            if updated_count > 0:
                db.commit()
                logger.debug(f"Analyzed and updated {updated_count} logs.")

        except Exception as e:
            logger.error(f"Database error: {e}")
            db.rollback()
        finally:
            db.close()

# Singleton instance
threat_analyzer = ThreatAnalyzerService()

