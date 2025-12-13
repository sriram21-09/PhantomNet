import unittest
import os
import sys
from sqlalchemy import create_engine, text

# 1. SETUP PATHS
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# 2. SIMPLE IMPORT
try:
    from ingestor.log_ingestor import ingest_logs
    print("✅ Imports Successful!")
except ImportError as e:
    print(f"❌ Import Failed: {e}")
    sys.exit(1)

# ⚠️ REPLACE WITH YOUR PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

class TestIngestor(unittest.TestCase):
    
    def setUp(self):
        self.test_file_path = os.path.join(current_dir, "test_logs.json")
        with open(self.test_file_path, 'w') as f:
            f.write('{"timestamp": "2025-01-01 10:00:00", "src_ip": "1.1.1.1", "honeypot_type": "test", "port": 80}\n')
            f.write('{"timestamp": "2025-01-01 10:05:00", "src_ip": "2.2.2.2", "honeypot_type": "test", "port": 80}\n')

    def test_ingest_function(self):
        print("\n🧪 Testing Ingestor...")
        engine = create_engine(DATABASE_URL)
        
        # Check count BEFORE
        with engine.connect() as conn:
            before = conn.execute(text("SELECT COUNT(*) FROM events")).scalar()

        # Run Ingestor
        ingest_logs(self.test_file_path)

        # Check count AFTER
        with engine.connect() as conn:
            after = conn.execute(text("SELECT COUNT(*) FROM events")).scalar()

        print(f"   Rows Before: {before} -> After: {after}")
        self.assertTrue(after >= before + 2)

    def tearDown(self):
        if os.path.exists(self.test_file_path):
            try:
                os.remove(self.test_file_path)
            except:
                pass

if __name__ == "__main__":
    unittest.main()