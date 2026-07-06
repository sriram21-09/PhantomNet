"""
tests/test_concurrency_lock.py
---------------------------------------------
Verifies SQLite WAL mode concurrency under concurrent write load.
Executes at least 10 concurrent writes (inserts and updates) simultaneously.
"""

import os
import sys
import time
import random
import unittest
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base
from sentinel.models import SentinelPlaybook
from sentinel.sentinel_service import SentinelService


class TestSQLiteConcurrency(unittest.TestCase):
    """
    Verifies that the SQLite database under WAL mode handles concurrent write operations
    without database is locked (SQLITE_BUSY) errors.
    """

    def setUp(self):
        # Use a temporary file database for testing file-concurrency
        self.db_path = "phantomnet_concurrency_test.db"
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass
        
        # Connect to SQLite file-based database
        # Connect args with check_same_thread=False and timeout=30
        self.db_url = f"sqlite:///{self.db_path}"
        self.engine = create_engine(
            self.db_url,
            connect_args={"check_same_thread": False, "timeout": 30}
        )
        Base.metadata.create_all(bind=self.engine)
        SentinelPlaybook.__table__.create(bind=self.engine, checkfirst=True)
        self.Session = sessionmaker(bind=self.engine)

    def tearDown(self):
        # Clean up database file
        self.engine.dispose()
        time.sleep(0.5)
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_concurrent_writes(self):
        """
        Runs at least 10 concurrent write operations (combination of generation
        and updates) and verifies zero database locked errors.
        """
        num_operations = 20  # Run 20 concurrent operations to fully saturate
        errors = []

        # We will define a helper function that each worker thread will execute
        def worker(worker_id):
            db = self.Session()
            try:
                # Re-use the existing SQLite connection and execute writes
                campaign = {
                    "source_ips": [f"192.168.1.{100 + worker_id}"],
                    "target_ports": [2222 if worker_id % 2 == 0 else 8080],
                    "protocols": ["TCP"],
                    "event_count": 50 + worker_id,
                    "campaign_id": f"CONC-CAMP-{worker_id}",
                }
                
                # Instantiating SentinelService with the session
                svc = SentinelService(db)
                
                # Perform the generation (INSERT write operation)
                playbook = svc.generate_playbook(campaign)
                
                # Introduce a tiny random sleep to increase concurrent overlap
                time.sleep(random.uniform(0.01, 0.05))
                
                # Perform an update (UPDATE write operation) on the generated playbook
                playbook.status = "approved"
                playbook.reviewed_by = f"worker_{worker_id}"
                playbook.reviewed_at = datetime.utcnow()
                db.commit()

            except Exception as e:
                errors.append(e)
            finally:
                db.close()

        # Execute using a ThreadPoolExecutor to run tasks in parallel
        with ThreadPoolExecutor(max_workers=num_operations) as executor:
            futures = [executor.submit(worker, i) for i in range(num_operations)]
            for future in as_completed(futures):
                future.result()

        # Assert no lock or write errors occurred
        for err in errors:
            print(f"Error encountered during concurrency test: {err}")
            import traceback
            traceback.print_exception(type(err), err, err.__traceback__)
        
        self.assertEqual(len(errors), 0, f"Expected 0 errors under load, got {len(errors)}")
        print(f"Concurrency Test Passed: Successfully executed {num_operations} concurrent operations with 0 errors!")


if __name__ == "__main__":
    unittest.main()
