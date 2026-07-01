"""
tests/test_week15_day3_pagination.py
--------------------------------------
Week 15, Day 3 — Pagination support for GET /api/sentinel/playbooks

Tests page/per_page query params, paginated response format,
validation, defaults, edge cases, and filtering with pagination.

Phase 5, Week 3 (Week 15), Day 3
"""

import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base
from sentinel.models import SentinelPlaybook
from api.sentinel import router
from database.database import get_db


from sqlalchemy.pool import StaticPool

# ---------------------------------------------------------------------------
# Module-level test infrastructure (shared across all test classes)
# ---------------------------------------------------------------------------
_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
Base.metadata.create_all(bind=_engine)
SentinelPlaybook.__table__.create(bind=_engine, checkfirst=True)
_TestSession = sessionmaker(bind=_engine)

_app = FastAPI()
_app.include_router(router)


def _override_get_db():
    db = _TestSession()
    try:
        yield db
    finally:
        db.close()


_app.dependency_overrides[get_db] = _override_get_db
_client = TestClient(_app)

BT = datetime(2026, 7, 1, 8, 0, 0)


def _seed_playbooks(count=25):
    """Insert N playbooks with varying data for pagination testing."""
    db = _TestSession()
    statuses = ["pending", "approved", "rejected", "pending", "pending"]
    attack_types = ["SSH_AUTH_FAILURE", "HTTP_SCANNER_BEHAVIOR", "PORT_SCAN"]

    for i in range(count):
        pb = SentinelPlaybook(
            playbook_id=f"PB-TEST-{i+1:04d}",
            src_ip=f"10.0.0.{i % 255}",
            dst_port=[2222, 8080, 2121][i % 3],
            protocol="TCP",
            attack_type=attack_types[i % 3],
            threat_score=50.0 + (i % 40),
            confidence_score=0.5 + (i % 5) * 0.1,
            severity=["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
            technique_id=["T1110.001", "T1190", "T1046"][i % 3],
            technique_name=["Brute Force", "Exploit App", "Network Discovery"][i % 3],
            tactic=["Credential Access", "Initial Access", "Discovery"][i % 3],
            mitre_url=f"https://attack.mitre.org/techniques/T{1000+i}/",
            snort_rule=f'alert tcp any any -> any any (msg:"test-{i}"; sid:{1000+i}; rev:1;)',
            sigma_rule=f"title: Test Rule {i}\nlogsource:\n  category: network_traffic\n  product: phantomnet",
            playbook_name=f"Test Playbook {i+1}",
            playbook_content=f"# Test Playbook {i+1}\n\nContent here..." + "x" * 200,
            template_name="brute_force_response.yaml.j2",
            status=statuses[i % 5],
            created_at=BT + timedelta(minutes=i),
        )
        db.add(pb)
    db.commit()
    db.close()
    return count


# Seed 25 playbooks for tests
_seed_playbooks(25)


# ===================================================================
# TEST CLASSES
# ===================================================================


class TestPaginationDefaults(unittest.TestCase):
    """Verify default page=1, per_page=20 when not specified."""

    def test_defaults_page_1_per_page_20(self):
        r = _client.get("/api/sentinel/playbooks")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["page"], 1)
        self.assertEqual(data["per_page"], 20)

    def test_default_returns_20_items(self):
        r = _client.get("/api/sentinel/playbooks")
        data = r.json()
        self.assertEqual(len(data["playbooks"]), 20)

    def test_default_total_is_25(self):
        r = _client.get("/api/sentinel/playbooks")
        data = r.json()
        self.assertEqual(data["total"], 25)

    def test_response_has_required_keys(self):
        r = _client.get("/api/sentinel/playbooks")
        data = r.json()
        self.assertIn("total", data)
        self.assertIn("page", data)
        self.assertIn("per_page", data)
        self.assertIn("playbooks", data)

    def test_response_status_success(self):
        r = _client.get("/api/sentinel/playbooks")
        data = r.json()
        self.assertEqual(data["status"], "success")


class TestPaginationParams(unittest.TestCase):
    """Verify page/per_page query parameters work correctly."""

    def test_page_1_per_page_5(self):
        r = _client.get("/api/sentinel/playbooks?page=1&per_page=5")
        data = r.json()
        self.assertEqual(data["page"], 1)
        self.assertEqual(data["per_page"], 5)
        self.assertEqual(len(data["playbooks"]), 5)
        self.assertEqual(data["total"], 25)

    def test_page_2_per_page_5(self):
        r = _client.get("/api/sentinel/playbooks?page=2&per_page=5")
        data = r.json()
        self.assertEqual(data["page"], 2)
        self.assertEqual(len(data["playbooks"]), 5)

    def test_page_3_per_page_10(self):
        r = _client.get("/api/sentinel/playbooks?page=3&per_page=10")
        data = r.json()
        self.assertEqual(data["page"], 3)
        self.assertEqual(len(data["playbooks"]), 5)

    def test_per_page_1_returns_one(self):
        r = _client.get("/api/sentinel/playbooks?page=1&per_page=1")
        data = r.json()
        self.assertEqual(len(data["playbooks"]), 1)

    def test_per_page_100_returns_all(self):
        r = _client.get("/api/sentinel/playbooks?page=1&per_page=100")
        data = r.json()
        self.assertEqual(len(data["playbooks"]), 25)

    def test_pages_dont_overlap(self):
        r1 = _client.get("/api/sentinel/playbooks?page=1&per_page=5")
        r2 = _client.get("/api/sentinel/playbooks?page=2&per_page=5")
        ids1 = {p["id"] for p in r1.json()["playbooks"]}
        ids2 = {p["id"] for p in r2.json()["playbooks"]}
        self.assertEqual(len(ids1 & ids2), 0, "Pages should not overlap")

    def test_all_pages_cover_total(self):
        all_ids = set()
        for page in range(1, 6):
            r = _client.get(f"/api/sentinel/playbooks?page={page}&per_page=5")
            for p in r.json()["playbooks"]:
                all_ids.add(p["id"])
        self.assertEqual(len(all_ids), 25)

    def test_total_stays_constant_across_pages(self):
        for page in [1, 2, 3]:
            r = _client.get(f"/api/sentinel/playbooks?page={page}&per_page=10")
            self.assertEqual(r.json()["total"], 25)


class TestPaginationValidation(unittest.TestCase):
    """Verify validation for page (>= 1) and per_page (1-100)."""

    def test_page_0_rejected(self):
        r = _client.get("/api/sentinel/playbooks?page=0")
        self.assertEqual(r.status_code, 422)

    def test_page_negative_rejected(self):
        r = _client.get("/api/sentinel/playbooks?page=-1")
        self.assertEqual(r.status_code, 422)

    def test_per_page_0_rejected(self):
        r = _client.get("/api/sentinel/playbooks?per_page=0")
        self.assertEqual(r.status_code, 422)

    def test_per_page_101_rejected(self):
        r = _client.get("/api/sentinel/playbooks?per_page=101")
        self.assertEqual(r.status_code, 422)

    def test_per_page_negative_rejected(self):
        r = _client.get("/api/sentinel/playbooks?per_page=-5")
        self.assertEqual(r.status_code, 422)

    def test_page_1_valid(self):
        r = _client.get("/api/sentinel/playbooks?page=1")
        self.assertEqual(r.status_code, 200)

    def test_per_page_1_valid(self):
        r = _client.get("/api/sentinel/playbooks?per_page=1")
        self.assertEqual(r.status_code, 200)

    def test_per_page_100_valid(self):
        r = _client.get("/api/sentinel/playbooks?per_page=100")
        self.assertEqual(r.status_code, 200)


class TestPaginationEdgeCases(unittest.TestCase):
    """Test last page, beyond last page."""

    def test_last_page_partial(self):
        """25 items, per_page=10 → page 3 should have 5 items."""
        r = _client.get("/api/sentinel/playbooks?page=3&per_page=10")
        data = r.json()
        self.assertEqual(data["total"], 25)
        self.assertEqual(len(data["playbooks"]), 5)

    def test_beyond_last_page_empty(self):
        r = _client.get("/api/sentinel/playbooks?page=100&per_page=5")
        data = r.json()
        self.assertEqual(data["total"], 25)
        self.assertEqual(len(data["playbooks"]), 0)
        self.assertEqual(data["page"], 100)

    def test_exact_page_boundary(self):
        """25 items, per_page=25 → page 1 has 25, page 2 has 0."""
        r1 = _client.get("/api/sentinel/playbooks?page=1&per_page=25")
        r2 = _client.get("/api/sentinel/playbooks?page=2&per_page=25")
        self.assertEqual(len(r1.json()["playbooks"]), 25)
        self.assertEqual(len(r2.json()["playbooks"]), 0)

    def test_single_item_per_page(self):
        for page in range(1, 26):
            r = _client.get(f"/api/sentinel/playbooks?page={page}&per_page=1")
            data = r.json()
            self.assertEqual(len(data["playbooks"]), 1, f"Page {page} should have 1 item")
        r = _client.get("/api/sentinel/playbooks?page=26&per_page=1")
        self.assertEqual(len(r.json()["playbooks"]), 0)


class TestPaginationWithFilters(unittest.TestCase):
    """Test pagination combined with status and attack_type filters."""

    def test_status_filter_with_pagination(self):
        r = _client.get("/api/sentinel/playbooks?status=pending&page=1&per_page=5")
        data = r.json()
        self.assertEqual(r.status_code, 200)
        for p in data["playbooks"]:
            self.assertEqual(p["status"], "pending")
        self.assertLess(data["total"], 25)

    def test_attack_type_filter_with_pagination(self):
        r = _client.get("/api/sentinel/playbooks?attack_type=SSH_AUTH_FAILURE&page=1&per_page=100")
        data = r.json()
        for p in data["playbooks"]:
            self.assertEqual(p["attack_type"], "SSH_AUTH_FAILURE")

    def test_filtered_pagination_total_consistency(self):
        r1 = _client.get("/api/sentinel/playbooks?status=pending&page=1&per_page=3")
        r2 = _client.get("/api/sentinel/playbooks?status=pending&page=2&per_page=3")
        self.assertEqual(r1.json()["total"], r2.json()["total"])

    def test_no_match_filter_returns_empty(self):
        r = _client.get("/api/sentinel/playbooks?status=nonexistent&page=1&per_page=10")
        data = r.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(len(data["playbooks"]), 0)


class TestPlaybookSummaryFields(unittest.TestCase):
    """Verify each playbook in paginated response has correct fields."""

    def test_summary_has_required_fields(self):
        r = _client.get("/api/sentinel/playbooks?page=1&per_page=3")
        data = r.json()
        expected_keys = [
            "id", "playbook_id", "src_ip", "dst_port", "protocol",
            "attack_type", "threat_score", "technique_id", "technique_name",
            "tactic", "playbook_name", "status", "created_at", "updated_at",
        ]
        for p in data["playbooks"]:
            for key in expected_keys:
                self.assertIn(key, p, f"Missing key: {key}")

    def test_summary_excludes_heavy_fields(self):
        r = _client.get("/api/sentinel/playbooks?page=1&per_page=3")
        data = r.json()
        for p in data["playbooks"]:
            self.assertNotIn("playbook_content", p)
            self.assertNotIn("snort_rule", p)
            self.assertNotIn("sigma_rule", p)


if __name__ == "__main__":
    unittest.main()
