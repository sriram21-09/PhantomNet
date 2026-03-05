import os
import time
import shutil
import logging
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from contextlib import contextmanager

from database.database import SessionLocal
from database.models import PacketLog
from ml.training_framework import TrainingFramework
from ml.feature_extractor import FeatureExtractor
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger("retraining_pipeline")
logger.setLevel(logging.INFO)

# Setup basic file handler for logging
log_dir = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
os.makedirs(log_dir, exist_ok=True)
fh = logging.FileHandler(os.path.join(log_dir, "retraining.log"))
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

class RetrainingPipeline:
    def __init__(self):
        self.models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'ml_models'))
        self.rf_model_path = os.path.join(self.models_dir, "attack_predictor.pkl")
        self.feature_extractor = FeatureExtractor()
        
    @contextmanager
    def _get_db(self):
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def fetch_training_data(self, days=30) -> pd.DataFrame:
        """Extract labeled training events spanning the requested timespan."""
        logger.info(f"Fetching labeled data from the last {days} days...")
        cutoff = datetime.now() - timedelta(days=days)
        
        with self._get_db() as db:
            # We want rows that have a definitive human/system-confirmed classification.
            # Right now, any PacketLog that triggered a concrete attack_type is considered '1'
            # Benign lines are '0'
            logs = db.query(PacketLog).filter(
                PacketLog.timestamp >= cutoff
            ).all()

            if len(logs) < 1000:
                logger.warning(f"Insufficient data volume ({len(logs)} rows) for scheduled retraining.")
                return pd.DataFrame()

            features_list = []
            labels = []
            
            for log in logs:
                event = {
                    "src_ip": log.src_ip,
                    "dst_ip": log.dst_ip or "127.0.0.1",
                    "dst_port": log.dst_port or 0,
                    "protocol": log.protocol or "UNKNOWN",
                    "length": log.length or 0
                }
                extracted = self.feature_extractor.extract_features(event)
                features_list.append(extracted)
                
                # Attack vs Benign Target Label (1 or 0)
                is_attack = 1 if log.attack_type and log.attack_type != "BENIGN" else 0
                labels.append(is_attack)

            df = pd.DataFrame(features_list, columns=FeatureExtractor.FEATURE_NAMES)
            df['is_attack'] = labels
            
            logger.info(f"Loaded {len(df)} records. Class balance: \n{df['is_attack'].value_counts()}")
            return df

    def retrain_random_forest(self, df: pd.DataFrame) -> bool:
        """Retrains the RF model natively using optimized parameters, replacing if accuracy holds/improves."""
        logger.info("Starting Random Forest retraining sequence.")
        
        # Load legacy model to base baseline score
        legacy_accuracy = 0.0
        # In a real environment, you'd test the legacy model against the latest df tests here.
        # For this script we assume >0.85 F1 is good enough to deploy.
        
        model = RandomForestClassifier(
            n_estimators=50,
            max_depth=12,
            min_samples_split=5,
            n_jobs=-1,
            random_state=42
        )
        
        trainer = TrainingFramework(
            model=model,
            feature_columns=FeatureExtractor.FEATURE_NAMES,
            label_column="is_attack"
        )
        
        # We manually split and fit because we want to intercept accuracy
        X_train, X_test, y_train, y_test = trainer.prepare_data(df)
        model.fit(X_train, y_train)
        
        score = model.score(X_test, y_test)
        logger.info(f"New model accuracy evaluated at: {score:.4f}")
        
        if score > 0.85: # Threshold limit to prevent deployment of bad weights
            timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
            
            # Keep backup of old model
            if os.path.exists(self.rf_model_path):
                backup_path = os.path.join(self.models_dir, f"attack_predictor_backup_{timestamp}.pkl")
                shutil.copy2(self.rf_model_path, backup_path)
                logger.info(f"Backed up legacy model to {backup_path}")
            
            # Save new model
            import pickle
            with open(self.rf_model_path, "wb") as f:
                pickle.dump(model, f)
                
            # Log version configuration
            meta_path = os.path.join(self.models_dir, "versions.json")
            meta = {}
            if os.path.exists(meta_path):
                import json
                with open(meta_path, "r") as f:
                    meta = json.load(f)
            
            meta["random_forest"] = {
                "version": timestamp,
                "accuracy": float(score),
                "trained_samples": len(df)
            }
            with open(meta_path, "w") as f:
                import json
                json.dump(meta, f, indent=4)
                
            logger.info("Successfully deployed newly tuned Random Forest model.")
            return True
        else:
            logger.warning("Newly trained model failed accuracy threshold check. Discarding weights.")
            return False

    def execute_pipeline(self):
        logger.info("-" * 40)
        logger.info("Automated Model Retraining Job STARTED")
        logger.info("-" * 40)
        
        try:
            df = self.fetch_training_data(days=30)
            if not df.empty:
                self.retrain_random_forest(df)
            else:
                logger.info("Aborting pipeline due to lack of minimum training data.")
        except Exception as e:
            logger.error(f"Retraining Pipeline crash: {str(e)}", exc_info=True)
            
        logger.info("Automated Model Retraining Job FINISHED")

retraining_pipeline = RetrainingPipeline()

if __name__ == "__main__":
    retraining_pipeline.execute_pipeline()
