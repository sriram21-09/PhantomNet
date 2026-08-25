import asyncio
import time
import sys
import os

# Set sqlite DB
os.environ["DATABASE_URL"] = "sqlite:///./phantomnet.db"

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from main import app
# pyrefly: ignore [missing-import]
from database.database import SessionLocal
# pyrefly: ignore [missing-import]
from sentinel.models import SentinelPlaybook
# pyrefly: ignore [missing-import]
from api.rate_limiter import check_rate_limit

# Bypass rate limit
app.dependency_overrides[check_rate_limit] = lambda: None

import httpx

async def make_request(client, i):
    payload = {
        "source_ips": [f"192.168.1.{i%250 + 1}"],
        "target_ports": [80],
        "protocols": ["TCP"],
        "event_count": 5,
        "campaign_id": f"STRESS-TEST-{i}"
    }
    try:
        response = await client.post("/api/sentinel/generate", json=payload)
        return response.status_code, response.json()
    except Exception as e:
        return 500, str(e)

async def main():
    start_time = time.time()
    success_count = 0
    failure_count = 0
    errors = []

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        tasks = [make_request(client, i) for i in range(100)]
        results = await asyncio.gather(*tasks)

        for status, res in results:
            if status == 200:
                success_count += 1
            else:
                failure_count += 1
                errors.append(res)

    end_time = time.time()
    
    print("Stress Test Results")
    print("-------------------")
    print(f"Total time: {end_time - start_time:.2f} seconds")
    print(f"Successful generation requests: {success_count}")
    print(f"Failed requests: {failure_count}")
    
    if failure_count > 0:
        print("\nErrors encountered:")
        for err in errors[:5]:
            print(f" - {err}")
        if len(errors) > 5:
            print(f"   ... and {len(errors) - 5} more")

    print("\nDatabase Integrity Check")
    print("------------------------")
    
    # Check DB
    try:
        db = SessionLocal()
        playbooks = db.query(SentinelPlaybook).filter(
            SentinelPlaybook.src_ip.like("192.168.1.%")
        ).all()
        print(f"Playbooks found in DB matching 192.168.1.*: {len(playbooks)}")
        if len(playbooks) == 100:
            print("SUCCESS: Database integrity verified, all 100 playbooks stored.")
        else:
            print(f"WARNING: Expected 100 playbooks, but found {len(playbooks)}.")
    except Exception as e:
        print(f"DB Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(main())
