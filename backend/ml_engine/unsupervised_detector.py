import os
import time
import logging
import pickle
import pandas as pd
from typing import List, Dict, Any
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from database.database import SessionLocal
from database.models import PacketLog
from ml.feature_extractor import FeatureExtractor

logger = logging.getLogger("unsupervised_detector")

class UnsupervisedAnomalyDetector:
    def __init__(self):
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self.model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ml_models', 'iforest_baseline.pkl'))
        self.is_loaded = self.load_model()
        
    def load_model(self) -> bool:
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info("Loaded Isolation Forest baseline model.")
                return True
            except Exception as e:
                logger.error(f"Failed to load Isolation Forest: {e}")
        return False
        
    def train_baseline(self, days_back: int = 7):
        """
        Trains the Isolation Forest on the last N days of data, 
        assuming the majority is normal traffic.
        """
        logger.info(f"Training unsupervised baseline on last {days_back} days.")
        db: Session = SessionLocal()
        try:
            cutoff = datetime.now() - timedelta(days=days_back)
            # Limit to 50,000 to keep memory profile low during training
            logs = db.query(PacketLog).filter(
                PacketLog.timestamp >= cutoff
            ).order_by(PacketLog.timestamp.desc()).limit(50000).all()
            
            if not logs:
                logger.warning("No logs found for baseline training.")
                return False
                
            features_list = []
            for log in logs:
                event = {
                    "src_ip": log.src_ip,
                    "dst_ip": log.dst_ip or "127.0.0.1",
                    "dst_port": log.dst_port or 0,
                    "protocol": log.protocol or "UNKNOWN",
                    "length": log.length or 0
                }
                features = self.feature_extractor.extract_features(event)
                features_list.append(features)
                
            df = pd.DataFrame(features_list, columns=FeatureExtractor.FEATURE_NAMES)
            
            # Train Isolation Forest (contamination=0.01 expects 1% outliers)
            self.model = IsolationForest(
                n_estimators=100, 
                max_samples='auto', 
                contamination=0.01, 
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(df.values)
            
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
                
            self.is_loaded = True
            logger.info("Baseline training completed and model saved.")
            return True
        except Exception as e:
            logger.error(f"Error training baseline: {e}")
            return False
        finally:
            db.close()
            
    def predict_anomalies(self, events: List[Dict[str, Any]]) -> List[float]:
        """
        Predicts an anomaly score for a batch of events.
        Higher score = more anomalous.
        """
        if not self.is_loaded or not self.model:
            return [0.0] * len(events)
            
        features_list = [self.feature_extractor.extract_features(ev) for ev in events]
        df = pd.DataFrame(features_list, columns=FeatureExtractor.FEATURE_NAMES)
        
        try:
            # score_samples returns negative anomaly score (-1.0 to 0.0) 
            # Lower means more anomalous. We invert to make it positive.
            scores = self.model.score_samples(df.values)
            
            # Normalize approx 0 to 100 for threat score integration
            # The more negative, the higher the threat
            normalized_scores = [max(0.0, min(100.0, abs(s) * 150)) for s in scores]
            return normalized_scores
            
        except Exception as e:
            logger.error(f"Anomaly prediction failed: {e}")
            return [0.0] * len(events)

# Singleton
unsupervised_detector = UnsupervisedAnomalyDetector()
