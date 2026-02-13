import unittest
import os
import sys
import random
from datetime import datetime
from sqlalchemy import create_engine, text

# 1. SETUP PATHS
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# 2. IMPORTS
try:
    from ingestor.log_ingestor import ingest_logs
    print("✅ Imports Successful!")
except ImportError as e:
    print(f"❌ Import Failed: {e}")
    sys.exit(1)

# ⚠️ REPLACE WITH YOUR PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@phantomnet_postgres:5432/phantomnet_db"

class TestIngestor(unittest.TestCase):
    
    def setUp(self):
        """Creates a fake log file with UNIQUE data every time."""
        self.test_file_path = os.path.join(current_dir, "test_logs.json")
        
        # Generate random IPs to avoid "UniqueViolation" errors
        self.rand_id = random.randint(100, 999)
        self.ip1 = f"192.168.1.{self.rand_id}"
        self.ip2 = f"192.168.1.{self.rand_id + 1}"
        
        # Use CURRENT time, not hardcoded past time
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"📝 Creating unique test data for IP: {self.ip1}")
        
        with open(self.test_file_path, 'w') as f:
            f.write(f'{{"timestamp": "{now_str}", "src_ip": "{self.ip1}", "honeypot_type": "test", "port": 80}}\n')
            f.write(f'{{"timestamp": "{now_str}", "src_ip": "{self.ip2}", "honeypot_type": "test", "port": 80}}\n')

    def test_ingest_function(self):
        print("\n🧪 Testing Ingestor...")
        engine = create_engine(DATABASE_URL)
        
        # 1. Check count BEFORE
        with engine.connect() as conn:
            before = conn.execute(text("SELECT COUNT(*) FROM events")).scalar()

        # 2. Run Ingestor
        ingest_logs(self.test_file_path)

        # 3. Check count AFTER
        with engine.connect() as conn:
            after = conn.execute(text("SELECT COUNT(*) FROM events")).scalar()

        print(f"   Rows Before: {before} -> After: {after}")
        
        # We expect at least 2 new events
        self.assertTrue(after >= before + 2)

    def tearDown(self):
        if os.path.exists(self.test_file_path):
            try:
                os.remove(self.test_file_path)
            except:
                pass

if __name__ == "__main__":
    unittest.main()
