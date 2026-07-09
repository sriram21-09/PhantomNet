import sys
import os
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.orm import Session

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.database import SessionLocal, engine
from database.models import Base, PacketLog
from ml_engine.campaign_clustering import CampaignClusterer


def test_campaign_clustering_non_utc_timezone(monkeypatch):
    """
    Verify that CampaignClusterer correctly identifies campaigns even when the host system
    is running in a non-UTC timezone (e.g., UTC+5:30).
    
    If the code used datetime.now(), the cutoff calculated would be in the future relative to UTC,
    causing recent naive UTC timestamps to be missed. Standardizing on datetime.utcnow() ensures correct query filtering.
    """
    # 1. Initialize DB tables
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()
    
    try:
        # Clean up database
        db.query(PacketLog).delete()
        db.commit()
        
        # 2. Seed mock PacketLog entries with high threat levels
        # These logs are generated in naive UTC.
        now_utc = datetime.utcnow()
        mock_logs = []
        for i in range(6):  # DBSCAN min_samples is 5
            log = PacketLog(
                src_ip=f"192.168.20.{10+i}",
                dst_ip="10.0.0.5",
                dst_port=80,
                protocol="TCP",
                length=150,
                threat_score=0.85,
                threat_level="HIGH",
                attack_type="scan",
                timestamp=now_utc - timedelta(minutes=5 * i)
            )
            mock_logs.append(log)
            
        db.add_all(mock_logs)
        db.commit()
        
        # 3. Simulate a host system in UTC+5:30 timezone by mocking datetime.now
        # datetime.now() will return a timezone-naive local time that is 5.5 hours ahead of UTC.
        simulated_local_time = now_utc + timedelta(hours=5, minutes=30)
        
        class MockedDatetime:
            @classmethod
            def now(cls):
                return simulated_local_time
            
            @classmethod
            def utcnow(cls):
                return now_utc
            
            @classmethod
            def fromtimestamp(cls, *args, **kwargs):
                return datetime.fromtimestamp(*args, **kwargs)
                
            @classmethod
            def strptime(cls, *args, **kwargs):
                return datetime.strptime(*args, **kwargs)
        
        # Patch datetime in the campaign_clustering module
        monkeypatch.setattr("ml_engine.campaign_clustering.datetime", MockedDatetime)
        
        # 4. Execute CampaignClusterer
        clusterer = CampaignClusterer()
        result = clusterer.identify_campaigns(hours_back=2)
        
        # 5. Assertions
        assert "error" not in result, f"Clustering failed with error: {result.get('error')}"
        assert result["campaign_count"] == 1, f"Expected 1 campaign, found {result['campaign_count']}"
        assert len(result["campaigns"]) == 1
        
        campaign = result["campaigns"][0]
        assert set(campaign["unique_sources"]) == {f"192.168.20.{10+j}" for j in range(6)}
        assert campaign["event_count"] == 6
        
    finally:
        db.query(PacketLog).delete()
        db.commit()
        db.close()
