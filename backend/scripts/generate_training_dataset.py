import csv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app_models import PacketLog
from backend.ml.feature_extractor import FeatureExtractor

DATABASE_URL = "sqlite:///./phantomnet.db"  # adjust if using Postgres
OUTPUT_FILE = "data/training_dataset.csv"
MIN_ROWS = 300

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

extractor = FeatureExtractor()

def main():
    db = SessionLocal()

    logs = (
        db.query(PacketLog)
        .order_by(PacketLog.timestamp.desc())
        .limit(MIN_ROWS)
        .all()
    )

    if len(logs) < MIN_ROWS:
        print(f"❌ Only {len(logs)} logs found. Need at least {MIN_ROWS}.")
        return

    feature_names = list(
        extractor.extract_features({
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
            "protocol": "TCP",
            "packet_length": 0,
            "timestamp": None
        }).keys()
    )

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(feature_names + ["label"])

        for log in logs:
            log_entry = {
                "src_ip": log.src_ip,
                "dst_ip": log.dst_ip,
                "protocol": log.protocol,
                "packet_length": log.length,
                "timestamp": log.timestamp
            }

            features = extractor.extract_features(log_entry)
            label = 1 if log.is_malicious else 0

            writer.writerow(list(features.values()) + [label])

    print(f"✅ Training dataset created: {OUTPUT_FILE}")
    print(f"📊 Rows: {len(logs)}")

    db.close()

if __name__ == "__main__":
    main()
