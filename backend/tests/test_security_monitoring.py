import sys
import os
import unittest
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

# Add the backend directory to the path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database.database import SessionLocal, engine
from database.models import Base, Alert, PacketLog
from services.alert_manager import AlertManager, alert_manager
from services.correlation_engine import CorrelationEngine
from services.baseline_monitor import BaselineMonitor

class TestSecurityMonitoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create tables if they don't exist (specifically the new Alerts table)
        Base.metadata.create_all(bind=engine)

    def setUp(self):
        self.db: Session = SessionLocal()
        # Clean up alerts before each test
        self.db.query(Alert).delete()
        self.db.query(PacketLog).delete()
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_alert_deduplication(self):
        """Test that AlertManager correctly deduplicates similar alerts."""
        manager = AlertManager(deduplication_window=60)
        
        # Create first alert
        a1 = manager.create_alert(
            level="WARNING",
            alert_type="TEST_TYPE",
            source_ip="1.2.3.4",
            description="Test alert 1"
        )
        self.assertIsNotNone(a1)
        
        # Attempt to create duplicate alert immediately
        a2 = manager.create_alert(
            level="WARNING",
            alert_type="TEST_TYPE",
            source_ip="1.2.3.4",
            description="Test alert 2"
        )
        self.assertIsNone(a2) # Should be deduplicated
        
        # Check database count
        count = self.db.query(Alert).count()
        self.assertEqual(count, 1)

    def test_correlation_multi_protocol(self):
        """Test CorrelationEngine detects multi-protocol access."""
        # Setup PacketLogs: One IP accessing SSH, HTTP, and FTP
        ip = "192.168.1.100"
        logs = [
            PacketLog(src_ip=ip, protocol="SSH", timestamp=datetime.utcnow()),
            PacketLog(src_ip=ip, protocol="HTTP", timestamp=datetime.utcnow()),
            PacketLog(src_ip=ip, protocol="FTP", timestamp=datetime.utcnow())
        ]
        self.db.add_all(logs)
        self.db.commit()
        
        engine = CorrelationEngine()
        engine._correlate_events()
        
        # Verify alert was created
        alert = self.db.query(Alert).filter(Alert.type == "CORRELATION", Alert.source_ip == ip).first()
        self.assertIsNotNone(alert)
        self.assertIn("Multi-protocol attack detected", alert.description)

    def test_baseline_spike_detection(self):
        """Test BaselineMonitor detects traffic spikes."""
        monitor = BaselineMonitor()
        
        # 1. Establish a low baseline (5 events/min)
        # We simulate this by setting the internal state
        monitor.average_events_per_minute = 5.0
        monitor.baseline_calculated = True
        
        # 2. Create a spike (100 events in the last minute)
        now = datetime.utcnow()
        logs = [PacketLog(src_ip=f"10.0.0.{i}", protocol="HTTP", timestamp=now) for i in range(100)]
        self.db.add_all(logs)
        self.db.commit()
        
        monitor._analyze_baseline()
        
        # Verify alert was created
        alert = self.db.query(Alert).filter(Alert.type == "BASELINE").first()
        self.assertIsNotNone(alert)
        self.assertIn("Traffic spike detected", alert.description)

if __name__ == "__main__":
    unittest.main()
