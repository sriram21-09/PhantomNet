import sys
import os
from sqlalchemy import text

# Add backend root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from database.database import SessionLocal, engine

def normalize_existing_scores():
    print("Normalizing existing threat scores in database...")
    db = SessionLocal()
    try:
        # Update scores > 1.0 to be on the 0.0-1.0 scale
        result = db.execute(text("UPDATE packet_logs SET threat_score = threat_score / 100.0 WHERE threat_score > 1.0"))
        db.commit()
        print(f"Successfully normalized {result.rowcount} records.")
    except Exception as e:
        print(f"Error during normalization: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    normalize_existing_scores()
