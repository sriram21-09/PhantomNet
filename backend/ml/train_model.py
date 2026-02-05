import logging
import os
import pandas as pd
import numpy as np

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app_models import PacketLog
from backend.ml.feature_extractor import FeatureExtractor
from backend.ml.anomaly_detector import AnomalyDetector

# --------------------------------------------------
# ENV + LOGGING
# --------------------------------------------------
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhantomNet-ML")

DATABASE_URL = os.getenv("DATABASE_URL") or "sqlite:///./phantomnet.db"

# --------------------------------------------------
# DATABASE
# --------------------------------------------------
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(bind=engine)

# --------------------------------------------------
# TRAINING PIPELINE
# --------------------------------------------------
def main():
    logger.info("🔌 Attempting connection to Database...")
    db = SessionLocal()
    logger.info("✅ Database Connection ESTABLISHED.")

    logs = (
        db.query(PacketLog)
        .order_by(PacketLog.timestamp.desc())
        .limit(300)
        .all()
    )

    if len(logs) < 300:
        logger.error(f"❌ Only {len(logs)} logs found. Need at least 300.")
        return

    extractor = FeatureExtractor()
    detector = AnomalyDetector()

    X = []
    for log in logs:
        log_entry = {
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "protocol": log.protocol,
            "packet_length": log.length,
            "timestamp": log.timestamp
        }
        features = extractor.extract_features(log_entry)
        X.append(list(features.values()))

    X = np.array(X, dtype=float)

    logger.info(f"🧠 Training IsolationForest on {X.shape[0]} samples ({X.shape[1]} features)")
    detector.model.fit(X)
    detector.is_trained = True

    detector.save()
    logger.info("✅ Model trained and saved successfully")

    db.close()


if __name__ == "__main__":
    main()
