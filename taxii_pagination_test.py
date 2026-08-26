import os
import sys
import time
from datetime import datetime, timedelta

# Force use of a local SQLite database for this test to avoid Postgres connection issues
os.environ["DATABASE_URL"] = "sqlite:///./taxii_pagination_test.db"
os.environ["TESTING"] = "1"
os.environ["ENVIRONMENT"] = "test"

# Add backend directory to path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, backend_path)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Import models and API
# pyrefly: ignore [missing-import]
from database.models import Base
# pyrefly: ignore [missing-import]
from sentinel.models import SentinelPlaybook
# pyrefly: ignore [missing-import]
from api.taxii import router as taxii_router, TaxiiContentNegotiationMiddleware
# pyrefly: ignore [missing-import]
from database.database import get_db

# Create engine and tables
engine = create_engine(os.environ["DATABASE_URL"], connect_args={"check_same_thread": False})
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def build_test_app() -> FastAPI:
    app = FastAPI(title="PhantomNet TAXII Test Server")
    app.add_middleware(TaxiiContentNegotiationMiddleware)
    app.include_router(taxii_router)
    return app

app = build_test_app()

def override_get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

# pyrefly: ignore [missing-import]
from api.taxii import get_taxii_user
def override_get_taxii_user():
    return type("User", (), {"username": "test", "status": "active"})()

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_taxii_user] = override_get_taxii_user
client = TestClient(app)

def seed_database():
    db = SessionLocal()
    print("Seeding database with 550 STIX bundle records...")
    base_time = datetime.utcnow() - timedelta(days=10)
    for i in range(550):
        # Create records sequentially to test added_after
        record_time = base_time + timedelta(minutes=i)
        pb = SentinelPlaybook(
            playbook_id=f"PB-TEST-{i:04d}",
            created_at=record_time,
            updated_at=record_time,
            src_ip=f"10.0.0.{i % 255}",
            dst_port=22, # cowrie-ssh honeypot
            protocol="TCP",
            attack_type="SSH_AUTH_FAILURE",
            tactic="Credential Access",
            technique_id="T1110",
            status="approved"
        )
        db.add(pb)
        if i % 100 == 0:
            db.commit()
    db.commit()
    db.close()
    print("Database seeded.")

def run_pagination_test():
    collection_id = "honeypot-cowrie-ssh"
    
    print("\n--- Running TAXII Pagination Test ---")
    headers = {
        "Accept": "application/taxii+json;version=2.1"
    }
    
    metrics = []
    
    # Test pagination limits and offsets
    limit = 100
    offsets = [0, 100, 200, 300, 400, 500]
    total_objects = 0
    
    for offset in offsets:
        start_time = time.time()
        response = client.get(
            f"/taxii2/phantomnet/collections/{collection_id}/objects/?limit={limit}&next={offset}",
            headers=headers
        )
        end_time = time.time()
        elapsed = (end_time - start_time) * 1000
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.text}"
        data = response.json()
        
        expected_playbooks = 100 if offset <= 400 else 50
        reports_count = sum(1 for obj in data.get("objects", []) if obj.get("type") == "report")
        
        metrics.append({
            "offset": offset,
            "limit": limit,
            "response_time_ms": elapsed,
            "playbooks_returned": reports_count,
            "total_stix_objects": len(data.get("objects", []))
        })
        
        print(f"Page with offset {offset}: {reports_count} playbooks retrieved. Time: {elapsed:.2f}ms")
        assert reports_count == expected_playbooks, f"Expected {expected_playbooks} playbooks, got {reports_count}"
        total_objects += reports_count
        
    assert total_objects == 550, f"Expected 550 total playbooks retrieved, got {total_objects}"
    print(f"\nPagination successful. Total playbooks retrieved across pages: {total_objects}")
    
    # Generate the report
    report = "# TAXII Feed Pagination Test Report and Performance Metrics\n\n"
    report += "## Test Configuration\n"
    report += "- **Endpoint**: `GET /taxii2/phantomnet/collections/{id}/objects/`\n"
    report += "- **Collection**: `honeypot-cowrie-ssh`\n"
    report += "- **Total Seeded Records**: 550\n"
    report += "- **Pagination Limit**: 100\n\n"
    
    report += "## Performance Metrics\n"
    report += "| Offset | Limit | Playbooks Returned | Total STIX Objects | Response Time (ms) |\n"
    report += "|--------|-------|--------------------|--------------------|--------------------|\n"
    
    total_time = 0
    for m in metrics:
        report += f"| {m['offset']} | {m['limit']} | {m['playbooks_returned']} | {m['total_stix_objects']} | {m['response_time_ms']:.2f} |\n"
        total_time += m['response_time_ms']
        
    avg_time = total_time / len(metrics)
    report += f"\n**Average Response Time**: {avg_time:.2f} ms\n\n"
    
    report += "## Verification Results\n"
    report += "- ✅ Database successfully seeded with 550 STIX bundle records.\n"
    report += "- ✅ Pagination logic verified: `limit` and `next` tokens properly split results into pages.\n"
    report += "- ✅ Response times measured successfully.\n"
    report += "- ✅ Expected counts per page exactly match results.\n"
    
    with open("TAXII_pagination_report.md", "w", encoding="utf-8") as f:
        f.write(report)
        
    print(f"\nReport saved to TAXII_pagination_report.md")
    
if __name__ == "__main__":
    seed_database()
    run_pagination_test()
