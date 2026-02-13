import numpy as np
import pandas as pd
import joblib
import os
import logging
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure paths
# Assuming this file is in backend/services/
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest_optimized_v2.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler_v1.pkl")

# Feature columns must match training
FEATURE_COLS = [
    "packet_length", "protocol_encoding", "source_ip_event_rate",
    "destination_port_class", "threat_score", "malicious_flag_ratio",
    "attack_type_frequency", "time_of_day_deviation", "burst_rate",
    "packet_size_variance", "honeypot_interaction_count",
    "session_duration_estimate", "unique_destination_count",
    "rolling_average_deviation", "z_score_anomaly"
]

class BatchProcessor:
    def __init__(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        self.model = None
        self.scaler = None
        self.model_path = model_path
        self.scaler_path = scaler_path
        self._load_resources()

    def _load_resources(self):
        """Lazy load model and scaler"""
        if not os.path.exists(self.model_path):
             logger.error(f"Model not found at {self.model_path}")
             return
        
        try:
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            logger.info("BatchProcessor: Model and Scaler loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load model/scaler: {e}")

    def predict_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process a batch of events using vectorized operations.
        Returns the original events with 'anomaly_prediction' and 'anomaly_score' added.
        """
        if not events:
            return []
            
        if self.model is None:
            logger.warning("Model not loaded, skipping prediction.")
            return events

        # 1. Convert to DataFrame for easier feature extraction
        df = pd.DataFrame(events)
        
        # 2. Extract Features (Vectorized)
        # Ensure all required columns exist, fill missing with 0
        missing_cols = [col for col in FEATURE_COLS if col not in df.columns]
        if missing_cols:
            # Efficiently add missing columns with 0
            for col in missing_cols:
                df[col] = 0
                
        # Select only feature columns in correct order
        X = df[FEATURE_COLS].fillna(0).values
        
        # 3. Batch Scaling
        X_scaled = self.scaler.transform(X)
        
        # 4. Batch Prediction
        # Isolation Forest: -1 (Anomaly), 1 (Normal)
        y_pred_raw = self.model.predict(X_scaled)
        
        # Convert to 1 (Anomaly), 0 (Normal) for consistency with our API
        # Vectorized numpy operation
        y_pred = np.where(y_pred_raw == -1, 1, 0)
        
        # 5. Batch Scoring
        # Decision function: lower = more anomalous
        scores = self.model.decision_function(X_scaled)
        
        # 6. Attach results back to events
        # We process in order, so index matches
        results = []
        for i, event in enumerate(events):
            # Create a copy to avoid mutating original if needed, or just update
            enriched_event = event.copy()
            enriched_event["anomaly_prediction"] = int(y_pred[i])
            enriched_event["anomaly_score"] = float(scores[i])
            results.append(enriched_event)
            
        return results

    def process_realtime_buffer(self, buffer: List[Dict]) -> List[Dict]:
        """Wrapper for processing a buffer from the sniffer"""
        return self.predict_batch(buffer)
