"""
Verify Sentinel API — Week 14 Day 2 + Day 3 — 20-point test suite.

Tests (Day 2 — existing 5 endpoints):
  1. Router module imports correctly
  2. Router has correct prefix and tags
  3. All 10 route paths registered
  4. GET /playbooks returns paginated list
  5. GET /playbooks/{id} returns 404 for missing
  6. GET /stats returns correct structure
  7. GET /mitre/mapping returns all 12 techniques
  8. POST /generate creates a playbook
  9. Router imported in main.py
 10. Router included in main.py app

Tests (Day 3 — new 5 endpoints):
 11. PATCH /playbooks/{id}/approve updates three fields
 12. PATCH /playbooks/{id}/approve returns 404 for missing
 13. PATCH /playbooks/{id}/reject updates three fields
 14. PATCH /playbooks/{id}/reject returns 404 for missing
 15. POST /playbooks/{id}/export with format=markdown
 16. POST /playbooks/{id}/export with format=json
 17. POST /playbooks/{id}/export with invalid format returns 400
 18. GET /rules/snort returns paginated list
 19. GET /rules/sigma returns paginated list
 20. Input validation rejects empty reviewed_by
"""
import sys
sys.path.insert(0, "backend")

# Ensure tables exist
from database.database import engine, SessionLocal
from database.models import Base
from sentinel.models import SentinelPlaybook as _SP  # noqa: F401
Base.metadata.create_all(bind=engine)

# ------------------------------------------------------------------
# Test 1: Module imports
# ------------------------------------------------------------------
from api.sentinel import (
    router, list_playbooks, get_playbook, get_sentinel_stats,
    get_mitre_mappings, generate_playbook,
    approve_playbook, reject_playbook, export_playbook,
    list_snort_rules, list_sigma_rules,
    ReviewRequest,
)
print("Test 1  PASS: api.sentinel module imports correctly (all 10 endpoints + ReviewRequest)")

# ------------------------------------------------------------------
# Test 2: Router prefix & tags
# ------------------------------------------------------------------
assert router.prefix == "/api/sentinel", f"Expected prefix '/api/sentinel', got '{router.prefix}'"
assert "Sentinel" in router.tags, f"Expected 'Sentinel' in tags, got {router.tags}"
print("Test 2  PASS: Router prefix=/api/sentinel, tags=['Sentinel']")

# ------------------------------------------------------------------
# Test 3: All 10 route paths registered
# ------------------------------------------------------------------
route_paths = [r.path for r in router.routes]
expected_paths = [
    "/api/sentinel/playbooks",
    "/api/sentinel/playbooks/{playbook_id}",
    "/api/sentinel/stats",
    "/api/sentinel/mitre/mapping",
    "/api/sentinel/generate",
    "/api/sentinel/playbooks/{playbook_id}/approve",
    "/api/sentinel/playbooks/{playbook_id}/reject",
    "/api/sentinel/playbooks/{playbook_id}/export",
    "/api/sentinel/rules/snort",
    "/api/sentinel/rules/sigma",
]
for ep in expected_paths:
    assert ep in route_paths, f"Missing route: {ep}"
print(f"Test 3  PASS: All 10 routes registered")

# ------------------------------------------------------------------
# Test 4: GET /playbooks works (via direct function call)
# ------------------------------------------------------------------
db = SessionLocal()
try:
    result = list_playbooks(page=1, per_page=10, status=None, attack_type=None, db=db)
    assert result["status"] == "success"
    assert "total" in result
    assert "playbooks" in result
    assert isinstance(result["playbooks"], list)
    assert "page" in result
    assert "per_page" in result
    print(f"Test 4  PASS: GET /playbooks returns paginated list (total={result['total']})")
finally:
    pass

# ------------------------------------------------------------------
# Test 5: GET /playbooks/{id} returns 404 for missing
# ------------------------------------------------------------------
from fastapi import HTTPException
try:
    get_playbook(playbook_id=999999, db=db)
    assert False, "Should have raised HTTPException"
except HTTPException as exc:
    assert exc.status_code == 404
    print("Test 5  PASS: GET /playbooks/999999 returns 404")

# ------------------------------------------------------------------
# Test 6: GET /stats returns correct structure
# ------------------------------------------------------------------
stats = get_sentinel_stats(db=db)
assert stats["status"] == "success"
assert "total_playbooks" in stats
assert "pending" in stats
assert "approved" in stats
assert "rejected" in stats
assert "avg_threat_score" in stats
assert "top_attack_types" in stats
print(f"Test 6  PASS: GET /stats returns correct structure (total={stats['total_playbooks']})")

# ------------------------------------------------------------------
# Test 7: GET /mitre/mapping returns all 12 techniques
# ------------------------------------------------------------------
mitre = get_mitre_mappings()
assert mitre["status"] == "success"
assert mitre["total"] == 12, f"Expected 12 techniques, got {mitre['total']}"
assert len(mitre["mappings"]) == 12
# Verify structure of first mapping
first = mitre["mappings"][0]
assert "technique_id" in first
assert "technique_name" in first
assert "tactic" in first
assert "severity" in first
assert "signature" in first
print(f"Test 7  PASS: GET /mitre/mapping returns all 12 techniques")

# ------------------------------------------------------------------
# Test 8: POST /generate creates a playbook
# ------------------------------------------------------------------
from api.sentinel import GenerateRequest
req = GenerateRequest(
    source_ips=["10.0.0.50"],
    target_ports=[2222],
    protocols=["TCP"],
    event_count=100,
    campaign_id="TEST-API-001",
)
gen_result = generate_playbook(request=req, db=db)
assert gen_result["status"] == "success"
assert gen_result["playbook_id"].startswith("PB-")
assert gen_result["service_type"] == "SSH"
assert gen_result["attack_type"] == "SSH_AUTH_FAILURE"
assert gen_result["db_record_id"] > 0
pb_id = gen_result["playbook_id"]
test_db_id = gen_result["db_record_id"]
print(f"Test 8  PASS: POST /generate creates playbook (id={pb_id})")

# ------------------------------------------------------------------
# Test 9: Router imported in main.py
# ------------------------------------------------------------------
import importlib
main_source = open("backend/main.py", "r", encoding="utf-8").read()
assert "from api.sentinel import router as sentinel_router" in main_source
print("Test 9  PASS: Router imported in main.py")

# ------------------------------------------------------------------
# Test 10: Router included in main.py
# ------------------------------------------------------------------
assert "app.include_router(sentinel_router)" in main_source
print("Test 10 PASS: Router included in main.py app")

# ==================================================================
# Day 3 Tests — New 5 endpoints
# ==================================================================

# ------------------------------------------------------------------
# Test 11: PATCH /playbooks/{id}/approve updates three fields
# ------------------------------------------------------------------
review_req = ReviewRequest(reviewed_by="analyst_tester")
approve_result = approve_playbook(playbook_id=test_db_id, body=review_req, db=db)
assert approve_result["status"] == "success"
assert "approved" in approve_result["message"]
assert approve_result["playbook"]["status"] == "approved"
assert approve_result["playbook"]["reviewed_by"] == "analyst_tester"
assert approve_result["playbook"]["reviewed_at"] is not None
print(f"Test 11 PASS: PATCH /approve updates status, reviewed_by, reviewed_at")

# ------------------------------------------------------------------
# Test 12: PATCH /playbooks/{id}/approve returns 404 for missing
# ------------------------------------------------------------------
try:
    approve_playbook(playbook_id=999999, body=review_req, db=db)
    assert False, "Should have raised HTTPException"
except HTTPException as exc:
    assert exc.status_code == 404
    print("Test 12 PASS: PATCH /approve returns 404 for missing playbook")

# ------------------------------------------------------------------
# Test 13: PATCH /playbooks/{id}/reject updates three fields
# ------------------------------------------------------------------
reject_req = ReviewRequest(reviewed_by="senior_analyst")
reject_result = reject_playbook(playbook_id=test_db_id, body=reject_req, db=db)
assert reject_result["status"] == "success"
assert "rejected" in reject_result["message"]
assert reject_result["playbook"]["status"] == "rejected"
assert reject_result["playbook"]["reviewed_by"] == "senior_analyst"
assert reject_result["playbook"]["reviewed_at"] is not None
print(f"Test 13 PASS: PATCH /reject updates status, reviewed_by, reviewed_at")

# ------------------------------------------------------------------
# Test 14: PATCH /playbooks/{id}/reject returns 404 for missing
# ------------------------------------------------------------------
try:
    reject_playbook(playbook_id=999999, body=reject_req, db=db)
    assert False, "Should have raised HTTPException"
except HTTPException as exc:
    assert exc.status_code == 404
    print("Test 14 PASS: PATCH /reject returns 404 for missing playbook")

# ------------------------------------------------------------------
# Test 15: POST /playbooks/{id}/export with format=markdown
# ------------------------------------------------------------------
# Re-approve so we can export
approve_playbook(playbook_id=test_db_id, body=ReviewRequest(reviewed_by="exporter"), db=db)

export_md = export_playbook(playbook_id=test_db_id, format="markdown", db=db)
assert export_md.status_code == 200
assert "text/markdown" in export_md.media_type
assert export_md.headers.get("content-disposition") is not None
assert ".md" in export_md.headers.get("content-disposition", "")
print("Test 15 PASS: POST /export format=markdown returns .md file download")

# ------------------------------------------------------------------
# Test 16: POST /playbooks/{id}/export with format=json
# ------------------------------------------------------------------
# Reset status to test export again
row = db.query(_SP).filter(_SP.id == test_db_id).first()
row.status = "approved"
db.commit()

export_json = export_playbook(playbook_id=test_db_id, format="json", db=db)
assert export_json.status_code == 200
assert "application/json" in export_json.media_type
assert ".json" in export_json.headers.get("content-disposition", "")
print("Test 16 PASS: POST /export format=json returns .json file download")

# ------------------------------------------------------------------
# Test 17: POST /playbooks/{id}/export with invalid format returns 400
# ------------------------------------------------------------------
try:
    export_playbook(playbook_id=test_db_id, format="invalid_format", db=db)
    assert False, "Should have raised HTTPException for invalid format"
except HTTPException as exc:
    assert exc.status_code == 400
    assert "Invalid export format" in str(exc.detail)
    print("Test 17 PASS: POST /export with invalid format returns 400")

# ------------------------------------------------------------------
# Test 18: GET /rules/snort returns paginated list
# ------------------------------------------------------------------
snort_result = list_snort_rules(limit=10, offset=0, attack_type=None, db=db)
assert snort_result["status"] == "success"
assert "total" in snort_result
assert "rules" in snort_result
assert isinstance(snort_result["rules"], list)
assert "limit" in snort_result
assert "offset" in snort_result
# Verify rule structure if rules exist
if snort_result["rules"]:
    rule = snort_result["rules"][0]
    assert "snort_rule" in rule
    assert "playbook_id" in rule
    assert "attack_type" in rule
print(f"Test 18 PASS: GET /rules/snort returns paginated list (total={snort_result['total']})")

# ------------------------------------------------------------------
# Test 19: GET /rules/sigma returns paginated list
# ------------------------------------------------------------------
sigma_result = list_sigma_rules(limit=10, offset=0, attack_type=None, db=db)
assert sigma_result["status"] == "success"
assert "total" in sigma_result
assert "rules" in sigma_result
assert isinstance(sigma_result["rules"], list)
assert "limit" in sigma_result
assert "offset" in sigma_result
# Verify rule structure if rules exist
if sigma_result["rules"]:
    rule = sigma_result["rules"][0]
    assert "sigma_rule" in rule
    assert "playbook_id" in rule
    assert "attack_type" in rule
print(f"Test 19 PASS: GET /rules/sigma returns paginated list (total={sigma_result['total']})")

# ------------------------------------------------------------------
# Test 20: Input validation rejects empty reviewed_by
# ------------------------------------------------------------------
from pydantic import ValidationError
try:
    ReviewRequest(reviewed_by="")
    assert False, "Should have raised ValidationError for empty reviewed_by"
except ValidationError:
    print("Test 20 PASS: Input validation rejects empty reviewed_by")

# ------------------------------------------------------------------
# Cleanup: Remove test playbook
# ------------------------------------------------------------------
cleanup_row = db.query(_SP).filter_by(playbook_id=pb_id).first()
if cleanup_row:
    db.delete(cleanup_row)
    db.commit()

db.close()

print()
print("=" * 60)
print("ALL 20 TESTS PASSED — Sentinel API W14 Day 2+3 verified!")
print("=" * 60)
