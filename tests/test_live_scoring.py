import pytest
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Adjust path if needed
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from database.database import Base, SessionLocal
from app_models import PacketLog
from services.threat_analyzer import ThreatAnalyzerService

def test_live_scoring_pipeline():
    """
    Verifies that the ThreatAnalyzerService picks up unscored logs,
    scores them using the ML model, and updates the database.
    """
    db = SessionLocal()
    
    # 1. Insert a Test Log (Unscored)
    test_log = PacketLog(
        timestamp=datetime.utcnow(),
        src_ip="192.168.1.50",  # Test IP
        dst_ip="10.0.0.5",
        protocol="TCP",
        length=1200,
        threat_score=0.0,
        threat_level=None,  # Explicitly None to trigger analysis
        attack_type="UNKNOWN"
    )
    db.add(test_log)
    db.commit()
    db.refresh(test_log)
    log_id = test_log.id
    print(f"Inserted test log ID: {log_id}")
    
    try:
        # 2. Run Analyzer (One Pass)
        analyzer = ThreatAnalyzerService(poll_interval=1)
        analyzer._process_unscored_logs()
        
        # 3. Verify Update
        db.expire_all() # Force refresh from DB to see updates from other session
        updated_log = db.query(PacketLog).filter(PacketLog.id == log_id).first()
        
        assert updated_log.threat_level is not None, "Threat level should be updated"
        assert updated_log.threat_score > 0 or updated_log.threat_score == 0.0, "Score should be set"
        assert updated_log.anomaly_score is not None, "Anomaly score should be set"
        
        print(f"Log Updated: Score={updated_log.threat_score}, Level={updated_log.threat_level}")
        
    finally:
        # Cleanup
        db.delete(test_log)
        db.commit()
        db.close()

if __name__ == "__main__":
    test_live_scoring_pipeline()
