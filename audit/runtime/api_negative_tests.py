"""
audit/runtime/api_negative_tests.py
-----------------------------------
Executes negative testing and API fuzzing against key PhantomNet API endpoints:
- Malformed JSON payloads
- Missing required fields
- Wrong parameter data types
- Oversized request bodies
- Invalid enum values
- SQL injection strings
- Path traversal strings
- Missing authentication / insufficient role
Logs all responses, status codes, and error formats to audit/runtime/negative_test_results.json.
"""
import os
import sys
import json
from pathlib import Path
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "a" * 32
os.environ["HONEYPOT_SECRET_KEY"] = "b" * 32

from main import app
from middleware.auth import create_access_token, create_step_up_token
from database.database import get_db, Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Setup in-memory test DB
engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Base.metadata.create_all(bind=engine)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

# Seed users into in-memory DB so get_current_user succeeds
from database.models import User
from middleware.auth import hash_password
from datetime import datetime, timezone

db_init = TestingSessionLocal()
db_init.add_all([
    User(username="admin_test", email="admin@test.local", hashed_password=hash_password("Pass123!"), role="Admin", status="active", created_at=datetime.now(timezone.utc)),
    User(username="analyst_test", email="analyst@test.local", hashed_password=hash_password("Pass123!"), role="Analyst", status="active", created_at=datetime.now(timezone.utc)),
    User(username="viewer_test", email="viewer@test.local", hashed_password=hash_password("Pass123!"), role="Viewer", status="active", created_at=datetime.now(timezone.utc)),
])
db_init.commit()
db_init.close()

client = TestClient(app)

admin_token = create_access_token(data={"sub": "admin_test", "role": "Admin"})
analyst_token = create_access_token(data={"sub": "analyst_test", "role": "Analyst"})
viewer_token = create_access_token(data={"sub": "viewer_test", "role": "Viewer"})
admin_step_up = create_step_up_token("admin_test")

test_cases = [
    # 1. Malformed JSON
    {
        "name": "Malformed JSON on Ingestion Gateway",
        "method": "POST",
        "path": "/api/v1/ingest/event",
        "headers": {"Content-Type": "application/json"},
        "data": "{bad_json: missing_quotes,",
        "expected_status": [400, 422],
    },
    {
        "name": "Malformed JSON on Login",
        "method": "POST",
        "path": "/api/v1/admin/login",
        "headers": {"Content-Type": "application/json"},
        "data": "['not', 'a', 'dict']",
        "expected_status": [422],
    },
    # 2. Missing Fields
    {
        "name": "Missing password in Login",
        "method": "POST",
        "path": "/api/v1/admin/login",
        "json": {"username": "admin_test"},
        "expected_status": [422],
    },
    {
        "name": "Missing title in Cases creation",
        "method": "POST",
        "path": "/api/v1/cases/",
        "headers": {"Authorization": f"Bearer {admin_token}"},
        "json": {"description": "Missing title"},
        "expected_status": [422],
    },
    # 3. Type Confusion
    {
        "name": "String for integer port in Report schedule",
        "method": "POST",
        "path": "/api/v1/reports/schedule",
        "headers": {"Authorization": f"Bearer {admin_token}"},
        "json": {
            "name": "Weekly Audit",
            "template_type": "Executive Summary",
            "frequency": "weekly",
            "schedule_time": "12:00",
            "recipients": "admin@phantomnet.local",
            "day_of_week": 12345  # Should be string enum
        },
        "expected_status": [422],
    },
    # 4. Invalid Enum
    {
        "name": "Invalid frequency enum in Report schedule",
        "method": "POST",
        "path": "/api/v1/reports/schedule",
        "headers": {"Authorization": f"Bearer {admin_token}"},
        "json": {
            "name": "Hacked Report",
            "template_type": "Executive",
            "frequency": "every_second",  # Invalid
            "schedule_time": "12:00",
            "recipients": "hacker@test.local"
        },
        "expected_status": [422],
    },
    # 5. SQL Injection Strings
    {
        "name": "SQL Injection in IP block endpoint",
        "method": "POST",
        "path": "/active-defense/block/' OR '1'='1",
        "headers": {
            "Authorization": f"Bearer {admin_token}",
            "X-Step-Up-Token": admin_step_up
        },
        "expected_status": [400],
    },
    {
        "name": "SQL Injection in User Search query",
        "method": "GET",
        "path": "/api/v1/alerts?level=' UNION SELECT * FROM users--",
        "headers": {"Authorization": f"Bearer {admin_token}"},
        "expected_status": [200, 400],  # Should either sanitize and return empty or return 400
    },
    # 6. Path Traversal
    {
        "name": "Path traversal in PCAP download",
        "method": "GET",
        "path": "/api/v1/events/..%2F..%2Fetc%2Fpasswd/pcap",
        "headers": {"Authorization": f"Bearer {admin_token}"},
        "expected_status": [400, 404],
    },
    # 7. Oversized Payload (>1 MB)
    {
        "name": "Oversized JSON payload on Report schedule",
        "method": "POST",
        "path": "/api/v1/reports/schedule",
        "headers": {"Authorization": f"Bearer {admin_token}"},
        "json": {
            "name": "A" * 100000,  # Exceeds max_length=100
            "template_type": "Exec",
            "frequency": "daily",
            "schedule_time": "12:00",
            "recipients": "test@test.local"
        },
        "expected_status": [422],
    },
    # 8. Missing Authentication
    {
        "name": "Unauthenticated access to Alerts",
        "method": "GET",
        "path": "/api/v1/alerts",
        "expected_status": [401],
    },
    # 9. Insufficient Role
    {
        "name": "Viewer attempting User deletion",
        "method": "DELETE",
        "path": "/api/v1/admin/users/1",
        "headers": {"Authorization": f"Bearer {viewer_token}"},
        "expected_status": [403],
    }
]

results = []
print("=== Running API Negative & Fuzzing Tests ===")

for tc in test_cases:
    method = tc["method"]
    path = tc["path"]
    headers = tc.get("headers", {})
    
    kwargs = {"headers": headers}
    if "json" in tc:
        kwargs["json"] = tc["json"]
    elif "data" in tc:
        kwargs["content"] = tc["data"]

    response = client.request(method, path, **kwargs)
    status_ok = response.status_code in tc["expected_status"]
    
    res_entry = {
        "test_name": tc["name"],
        "method": method,
        "path": path,
        "actual_status": response.status_code,
        "expected_status": tc["expected_status"],
        "pass": status_ok,
        "response_sample": response.text[:200]
    }
    results.append(res_entry)
    verdict = "[PASS]" if status_ok else "[FAIL]"
    print(f"{verdict} {tc['name']} -> {response.status_code} (Expected: {tc['expected_status']})")

out_file = Path(__file__).resolve().parent / "negative_test_results.json"
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

passed = sum(1 for r in results if r["pass"])
print(f"\nTotal: {len(results)} | Passed: {passed} | Failed: {len(results) - passed}")
