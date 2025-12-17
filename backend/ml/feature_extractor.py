import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session
from database.models import Event, Session as DbSession

class FeatureExtractor:
    def __init__(self, db: Session):
        self.db = db

    def extract_features(self, session_id: int):
        """
        Reads raw events for a session and returns a dictionary of math features.
        """
        # 1. Fetch all events for this session
        events = self.db.query(Event).filter(Event.session_id == session_id).all()
        
        if not events:
            return None

        # 2. Convert to DataFrame (Easier for math)
        data = [
            {
                "timestamp": e.timestamp,
                "src_port": e.src_port,
                "honeypot": e.honeypot_type
            }
            for e in events
        ]
        df = pd.DataFrame(data)

        # 3. Calculate the Features ( The AI Inputs )
        
        # A. Duration (How long did they attack?)
        start_time = df['timestamp'].min()
        end_time = df['timestamp'].max()
        duration = (end_time - start_time).total_seconds()

        # B. Event Count (How aggressive?)
        event_count = len(df)

        # C. Port Variance (Did they try many ports?)
        unique_ports = df['src_port'].nunique()

        features = {
            "duration_seconds": duration,
            "event_count": event_count,
            "unique_ports": unique_ports,
            "events_per_second": event_count / (duration + 1) # +1 avoids divide by zero
        }

        return features

# 🧪 Quick Test (Run this file directly to check)
if __name__ == "__main__":
    from database.database import SessionLocal
    db = SessionLocal()
    
    print("-----------------------------------")
    print("🧪 Testing Feature Extractor Logic")
    print("-----------------------------------")
    
    # We need a fake session to test. 
    # If DB is empty, this might return None, which is fine for now.
    extractor = FeatureExtractor(db)
    
    # Just checking if the class loads correctly
    print("✅ FeatureExtractor class loaded successfully.")
    print("   Ready to be connected to the AI model.")
    
    db.close()