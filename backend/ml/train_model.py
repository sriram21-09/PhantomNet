import pandas as pd
import pickle
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.database import SessionLocal
from database.models import AttackSession
from ml.feature_extractor import FeatureExtractor
from sklearn.ensemble import RandomForestClassifier

def train_model():
    print("🔌 Connecting to Database...")
    db = SessionLocal()
    extractor = FeatureExtractor(db)
    
    sessions = db.query(AttackSession).all()
    print(f"📊 Found {len(sessions)} sessions in database.")

    if len(sessions) < 5:
        print("❌ Not enough data! Run 'python scripts/seed_data.py' first.")
        return

    training_data = []
    labels = []

    print("🧠 Extracting features...")
    for session in sessions:
        features = extractor.extract_features(session.id)
        
        training_data.append([
            features["duration_seconds"],
            features["event_count"],
            features["unique_ports"],
            features["events_per_second"]
        ])

        if features["events_per_second"] > 1.0 or features["unique_ports"] > 2:
            labels.append(1) 
        else:
            labels.append(0) 

    X = pd.DataFrame(training_data, columns=["duration", "event_count", "unique_ports", "eps"])
    y = labels

    print(f"🤖 Training Random Forest on {len(X)} records...")
    model = RandomForestClassifier(n_estimators=50)
    model.fit(X, y)

    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(current_dir, "threat_model.pkl")

    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    print(f"✅ Model Retrained & Saved at: {model_path}")
    db.close()

if __name__ == "__main__":
    train_model()
