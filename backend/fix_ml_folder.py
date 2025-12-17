import os

# Define the paths
base_dir = os.getcwd()
ml_dir = os.path.join(base_dir, "ml")

# 1. Ensure the 'ml' folder exists
if not os.path.exists(ml_dir):
    try:
        os.makedirs(ml_dir)
        print(f"✅ Created folder: {ml_dir}")
    except FileExistsError:
        print(f"✅ Folder already exists (that's fine): {ml_dir}")

# 2. Create __init__.py
init_path = os.path.join(ml_dir, "__init__.py")
with open(init_path, "w", encoding="utf-8") as f:
    f.write("") # Empty file
print("✅ Created __init__.py")

# 3. Create feature_extractor.py
extractor_code = """from sqlalchemy.orm import Session
from database.models import Event, AttackSession
from datetime import datetime

class FeatureExtractor:
    def __init__(self, db_session: Session):
        self.db = db_session

    def extract_features(self, session_id: int):
        session = self.db.query(AttackSession).filter(AttackSession.id == session_id).first()
        events = self.db.query(Event).filter(Event.session_id == session_id).all()
        
        if not session or not events:
            return {"duration_seconds": 0, "event_count": 0, "unique_ports": 0, "events_per_second": 0}

        start_time = events[-1].timestamp 
        end_time = events[0].timestamp
        duration = (end_time - start_time).total_seconds()
        
        if duration <= 0: duration = 1.0

        unique_ports = len(set(e.src_port for e in events))
        event_count = len(events)
        eps = event_count / duration

        return {
            "duration_seconds": duration,
            "event_count": event_count,
            "unique_ports": unique_ports,
            "events_per_second": eps
        }
"""
with open(os.path.join(ml_dir, "feature_extractor.py"), "w", encoding="utf-8") as f:
    f.write(extractor_code)
print("✅ Created feature_extractor.py")

# 4. Create train_model.py
trainer_code = """import pandas as pd
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
"""
with open(os.path.join(ml_dir, "train_model.py"), "w", encoding="utf-8") as f:
    f.write(trainer_code)
print("✅ Created train_model.py")
print("🎉 REPAIR COMPLETE!")