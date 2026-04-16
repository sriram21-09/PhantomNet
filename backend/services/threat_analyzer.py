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
from ml_engine.unsupervised_detector import unsupervised_detector
from database.database import get_db

# Automated Response
from services.response_executor import response_executor
from api.realtime import push_realtime_event
import asyncio

# PCAP Capture Integration
from services.pcap_analyzer import pcap_analyzer

# Configure logging
logger = logging.getLogger("threat_analyzer")
logger.setLevel(logging.INFO)


class ThreatAnalyzerService:
    def __init__(self, poll_interval: int = 2):
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._cache = {}  # Simple Dict Cache [IP -> {score, level, timestamp}]
        self._cache_ttl = 60  # Seconds
        self.running = False
        self.last_inference_ms = 0.0
        self.last_pattern_scan = datetime.now()
        self.pattern_scan_interval = 60  # Run advanced patterns every minute

        self._sequence_buffers = {}  # IP -> [buffer of up to 50 feature vectors]
        self.lstm_model = None
        self.lstm_scaler = None
        self.lstm_feature_cols = []
        self.is_mock_lstm = False
        
        # We will load the LSTM model in the background thread to avoid blocking startup

    def _load_lstm(self):
        self.lstm_model = None
        self.lstm_scaler = None
        self.lstm_feature_cols = []
        self.is_mock_lstm = False

        pkl_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "..", "..", "ml_models", "lstm_training_data.pkl"
            )
        )
        if os.path.exists(pkl_path):
            print(f"[THREAT_ANALYZER] Loading LSTM scaler from {pkl_path}...")
            try:
                with open(pkl_path, "rb") as f:
                    data = pickle.load(f)
                    self.lstm_scaler = data.get("scaler")
                    self.lstm_feature_cols = data.get("feature_cols", [])
            except Exception as e:
                logger.error(f"Failed to load LSTM scaler: {e}")

        h5_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "..", "..", "ml_models", "lstm_attack_predictor.h5"
            )
        )
        try:
            from tensorflow.keras.models import load_model

            if os.path.exists(h5_path):
                self.lstm_model = load_model(h5_path)
                print("[THREAT_ANALYZER] LSTM Model loaded successfully.")
        except Exception as e:
            logger.debug(
                f"Could not load Keras LSTM model ({e}). Looking for mock fallback."
            )
            mock_path = h5_path + ".mock.pkl"
            if os.path.exists(mock_path):
                print(f"[THREAT_ANALYZER] Loading mock LSTM fallback: {mock_path}...")
                with open(mock_path, "rb") as f:
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
            seq = np.array([self._sequence_buffers[ip]])  # shape (1, 50, num_features)
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
        if hasattr(self, "thread"):
            self.thread.join(timeout=2)
        logger.info("Threat Analyzer Service stopped.")

    def _run_loop(self):
        print(f"[THREAT_ANALYZER] Background analysis loop started (Poll: {self.poll_interval}s)")
        # Lazy load LSTM model in the thread
        try:
            self._load_lstm()
        except Exception as e:
            print(f"[THREAT_ANALYZER] FAILED to load LSTM in thread: {e}")

        while not self._stop_event.is_set():
            try:
                self._process_unscored_logs()

                # Check if it's time to run advanced patterns (Distributed Brute Force, Low & Slow)
                if (
                    datetime.now() - self.last_pattern_scan
                ).total_seconds() >= self.pattern_scan_interval:
                    self._process_advanced_patterns()
                    self.last_pattern_scan = datetime.now()

            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")

            time.sleep(self.poll_interval)

    def _get_cached_score(self, ip: str):
        """Returns cached score if valid."""
        if ip in self._cache:
            data = self._cache[ip]
            if datetime.now() - data["timestamp"] < timedelta(seconds=self._cache_ttl):
                return data
            else:
                del self._cache[ip]
        return None

    def _cache_score(self, ip: str, result):
        """Caches the scoring result."""
        self._cache[ip] = {"timestamp": datetime.now(), "result": result}

    def _process_advanced_patterns(self):
        db: Session = SessionLocal()
        try:
            detector = AdvancedPatternDetector(db)
            report = detector.run_all_checks()

            threats_found = False
            if report.get("distributed_brute_force_ssh"):
                logger.warning(
                    f"ADVANCED THREAT DETECTED: Distributed Brute Force: {len(report['distributed_brute_force_ssh'])} targets."
                )
                threats_found = True

            if report.get("low_and_slow_scans"):
                logger.warning(
                    f"ADVANCED THREAT DETECTED: Low and Slow scans from {len(report['low_and_slow_scans'])} sources."
                )
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
            # Check if unsupervised detector needs training (Non-blocking)
            total_logs = db.query(PacketLog).count()
            if not unsupervised_detector.is_loaded and not unsupervised_detector.is_training and total_logs > 10:
                logger.info("ThreatAnalyzer: Triggering background unsupervised training...")
                threading.Thread(target=unsupervised_detector.train_baseline, kwargs={"days_back": 7}, daemon=True).start()

            # Fetch logs where threat_level is NULL
            logs = (
                db.query(PacketLog)
                .filter(PacketLog.threat_level.is_(None))
                .order_by(PacketLog.timestamp.desc())
                .limit(500)
                .all()
            )  # Increased batch size to catch up with queue

            if not logs:
                return

            updated_count = 0
            inputs_for_batching = []
            log_mapping = []  # to map back response to the specific log

            # Find which ones need scoring vs cache
            for log in logs:
                cached = self._get_cached_score(log.src_ip)
                if cached:
                    result = cached["result"]
                    # Apply immediately from local analyzer cache
                    self._apply_threat_result(log, result)
                    updated_count += 1
                else:
                    inputs_for_batching.append(
                        ThreatInput(
                            src_ip=log.src_ip,
                            dst_ip=log.dst_ip or "127.0.0.1",
                            src_port=log.src_port or 0,
                            dst_port=log.dst_port or 0,
                            protocol=log.protocol or "UNKNOWN",
                            length=log.length or 0,
                        )
                    )
                    log_mapping.append(log)

            # Process the batch using vectorized API
            if inputs_for_batching:
                start_time = time.time()
                try:
                    from ml.threat_scoring_service import score_threat_batch

                    batch_results = score_threat_batch(inputs_for_batching)

                    # Compute unsupervised anomaly scores in bulk for speed
                    events_dicts = [
                        {
                            "src_ip": i.src_ip,
                            "dst_ip": i.dst_ip,
                            "dst_port": i.dst_port,
                            "protocol": i.protocol,
                            "length": i.length,
                        }
                        for i in inputs_for_batching
                    ]
                    unsupervised_scores = unsupervised_detector.predict_anomalies(
                        events_dicts
                    )

                    for idx, result in enumerate(batch_results):
                        if result:
                            log = log_mapping[idx]

                            # Apply Unsupervised Anomaly detection
                            anomaly_score = unsupervised_scores[idx]

                            # Apply LSTM sequence ensemble
                            lstm_score = self._compute_lstm_score(log.src_ip, log)

                            if lstm_score > 0:
                                # Ensemble Equation: 50% RF, 30% LSTM, 20% Unsupervised Anomaly baseline
                                # (Standardizing RF if it was 0-100, but it's now 0-1 in our updated scoring service)
                                rf_normalized = result.score if result.score <= 1.0 else result.score / 100.0
                                combined_score = (
                                    (rf_normalized * 0.5)
                                    + (lstm_score * 0.3)
                                    + (anomaly_score * 0.2)
                                )
                            else:
                                # Fallback Sequence (Buffer not full): 80% RF, 20% Unsupervised
                                rf_normalized = result.score if result.score <= 1.0 else result.score / 100.0
                                combined_score = (rf_normalized * 0.8) + (
                                    anomaly_score * 0.2
                                )

                            result.score = combined_score
                            if combined_score >= 0.8:
                                result.threat_level = "CRITICAL"
                            elif combined_score >= 0.6:
                                result.threat_level = "HIGH"
                            elif combined_score >= 0.4:
                                result.threat_level = "MEDIUM"
                            else:
                                result.threat_level = "LOW"

                            self._cache_score(log.src_ip, result)
                            self._apply_threat_result(log, result)
                            updated_count += 1

                    end_time = time.time()
                    inf_time_ms = (end_time - start_time) * 1000
                    self.last_inference_ms = round(inf_time_ms / len(inputs_for_batching), 2) if inputs_for_batching else 0.0
                    logger.debug(
                        f"Batch prediction complete. Time: {inf_time_ms:.2f}ms for {len(inputs_for_batching)} events."
                    )

                except Exception as e:
                    logger.error(f"Error in batch processing: {e}")

            if updated_count > 0:
                # Notify Topology Visualization of new activity
                try:
                    import asyncio
                    from api.topology import push_topology_event

                    asyncio.run(
                        push_topology_event("TRAFFIC_TICK", {"count": len(logs)})
                    )
                except Exception as ws_e:
                    logger.debug(f"Topology sync skipped: {ws_e}")

                db.commit()
                logger.debug(f"Analyzed and updated {updated_count} logs.")

        except Exception as e:
            logger.error(f"Database error: {e}")
            db.rollback()
        finally:
            db.close()

    def _apply_threat_result(self, log: PacketLog, result):
        """Helper to apply result entity to PacketLog object"""
        log.threat_score = result.score
        log.threat_level = result.threat_level
        log.confidence = result.confidence
        log.attack_type = result.decision
        log.is_malicious = result.threat_level in ["HIGH", "CRITICAL"]

        if log.is_malicious:
            try:
                import asyncio
                from api.topology import push_topology_event

                asyncio.run(
                    push_topology_event(
                        "THREAT_DETECTED",
                        {
                            "attacker_ip": log.src_ip,
                            "target_service": log.dst_port,
                            "threat_score": result.score,
                            "attack_type": result.decision,
                        },
                    )
                )
            except Exception as ws_e:
                logger.debug(f"Topology threat sync failed: {ws_e}")

        if result.threat_level in ["HIGH", "CRITICAL"]:
            try:
                response_executor.execute(
                    ip=log.src_ip,
                    threat_score=result.score * 100,
                    threat_level=result.threat_level,
                    protocol=log.protocol or "UNKNOWN",
                    details=f"Auto-detected: {result.decision}",
                )
            except Exception as e:
                logger.error(f"Response execution failed for {log.src_ip}: {e}")

            # PCAP Capture: trigger full capture for HIGH/CRITICAL threats
            try:
                capture_result = pcap_analyzer.start_capture(
                    event_id=log.id,
                    duration=60,
                )
                logger.info(
                    f"[PCAP] Triggered capture for event {log.id}: {capture_result.get('status')}"
                )
            except Exception as pcap_e:
                logger.error(f"[PCAP] Failed to trigger capture for {log.id}: {pcap_e}")

            # Extract IOCs from the threat and store them
            try:
                from database.models import IOC

                db = SessionLocal()
                existing = (
                    db.query(IOC)
                    .filter(IOC.value == log.src_ip, IOC.type == "IP")
                    .first()
                )
                if not existing:
                    new_ioc = IOC(
                        type="IP",
                        value=log.src_ip,
                        description=f"Auto-extracted from {result.threat_level} threat: {result.decision}",
                        threat_level=result.threat_level,
                        is_watchlist=True,
                    )
                    db.add(new_ioc)
                    db.commit()
                    logger.info(f"[IOC] Stored new IOC: {log.src_ip}")
                else:
                    existing.last_seen = datetime.now()
                    existing.threat_level = result.threat_level
                    db.commit()
                db.close()
            except Exception as ioc_e:
                logger.error(f"[IOC] Failed to store IOC for {log.src_ip}: {ioc_e}")


# Singleton instance
threat_analyzer = ThreatAnalyzerService()
