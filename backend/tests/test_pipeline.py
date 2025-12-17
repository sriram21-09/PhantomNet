import sys
import os
import pickle
import pandas as pd
from datetime import datetime

# Setup path to import from parent folders
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.database import SessionLocal, engine
from database.models import Base, Event, Session as DbSession
from ml.feature_extractor import FeatureExtractor

def test_full_pipeline():
    print("\n🚀 STARTING INTEGRATION TEST (Issue #23)...")
    
    # 1. Setup Database
    db = SessionLocal()
    Base.metadata.create_all(bind=engine)
    
    # 2. Simulate a Hacker Session (Create Fake Data)
    print("🔹 Step 1: Simulating Attack Data...")
    
    # Create a session
    test_session = DbSession(attacker_ip="192.168.1.66", start_time=datetime.utcnow())
    db.add(test_session)
    db.commit()
    
    # Create 10 fast login attempts (Brute Force pattern)
    for i in range(10):
        event = Event(
            source_ip="192.168.1.66",
            src_port=4444,
            honeypot_type="SSH",
            raw_data="Failed password for root",
            session_id=test_session.id,
            timestamp=datetime.utcnow()
        )
        db.add(event)
    db.commit()
    print(f"   ✅ Created Session ID: {test_session.id} with 10 events.")

    # 3. Run Feature Extraction (The Math)
    print("🔹 Step 2: Extracting Features...")
    extractor = FeatureExtractor(db)
    features = extractor.extract_features(test_session.id)
    print(f"   ✅ Features Calculated: {features}")

    # 4. Load the AI Brain (The Model)
    print("🔹 Step 3: Loading AI Model...")
    model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml", "threat_model.pkl")
    
    if not os.path.exists(model_path):
        print("   ❌ Model file not found! Did you finish Issue #20?")
        return

    with open(model_path, "rb") as f:
        model = pickle.load(f)
    print("   ✅ Model Loaded.")

    # 5. Make a Prediction
    print("🔹 Step 4: AI Prediction...")
    # Prepare input dataframe matching training format
    input_df = pd.DataFrame([features])
    
    # We only need the columns the model was trained on
    # (Check train_model.py for the exact order: duration, event_count, unique_ports, eps)
    input_vector = input_df[["duration_seconds", "event_count", "unique_ports", "events_per_second"]]
    input_vector.columns = ["duration", "event_count", "unique_ports", "eps"] # Rename to match training
    
    prediction = model.predict(input_vector)[0]
    confidence = model.predict_proba(input_vector).max()
    
    print("\n------------------------------------------------")
    if prediction == 1:
        print(f"🚨 RESULT: THREAT DETECTED! (Confidence: {confidence:.2f})")
    else:
        print(f"🛡️ RESULT: SAFE SESSION (Confidence: {confidence:.2f})")
    print("------------------------------------------------\n")
    
    # Cleanup (Optional: Delete the test data)
    db.close()

if __name__ == "__main__":
    test_full_pipeline()