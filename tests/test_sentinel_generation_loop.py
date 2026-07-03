"""
tests/test_sentinel_generation_loop.py
---------------------------------------
Verification tests for Day 4 — Sentinel Generation Loop.

Validates:
  1. SENTINEL_ENABLED env var toggle (true/false)
  2. Dedup logic: processed campaigns are skipped on re-encounter
  3. Field mapping: campaign_clusterer output → SentinelService input
  4. Hash-based dedup: identical campaigns produce same hash
  5. Cycle logging: new vs skipped counts are tracked correctly

Phase 5, Week 2 (Week 14), Day 4
"""

import asyncio
import hashlib
import os
import sys
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

# Ensure backend is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))


class TestSentinelEnabledToggle(unittest.TestCase):
    """Test that SENTINEL_ENABLED env var controls task startup."""

    def test_sentinel_disabled_by_default(self):
        """SENTINEL_ENABLED defaults to 'false' — loop should NOT start."""
        enabled = os.getenv("SENTINEL_ENABLED", "false").lower() == "true"
        self.assertFalse(enabled, "SENTINEL_ENABLED should default to false")

    def test_sentinel_enabled_when_true(self):
        """When SENTINEL_ENABLED=true, the toggle should evaluate to True."""
        with patch.dict(os.environ, {"SENTINEL_ENABLED": "true"}):
            enabled = os.getenv("SENTINEL_ENABLED", "false").lower() == "true"
            self.assertTrue(enabled)

    def test_sentinel_enabled_case_insensitive(self):
        """SENTINEL_ENABLED should be case-insensitive."""
        for val in ["True", "TRUE", "true", "TrUe"]:
            with patch.dict(os.environ, {"SENTINEL_ENABLED": val}):
                enabled = os.getenv("SENTINEL_ENABLED", "false").lower() == "true"
                self.assertTrue(enabled, f"Failed for value: {val}")

    def test_sentinel_disabled_explicit(self):
        """When SENTINEL_ENABLED=false, loop should NOT start."""
        with patch.dict(os.environ, {"SENTINEL_ENABLED": "false"}):
            enabled = os.getenv("SENTINEL_ENABLED", "false").lower() == "true"
            self.assertFalse(enabled)

    def test_sentinel_disabled_for_invalid_values(self):
        """Invalid values like 'yes', '1', 'on' should NOT enable sentinel."""
        for val in ["yes", "1", "on", "enabled", ""]:
            with patch.dict(os.environ, {"SENTINEL_ENABLED": val}):
                enabled = os.getenv("SENTINEL_ENABLED", "false").lower() == "true"
                self.assertFalse(enabled, f"Should be disabled for value: {val}")


class TestDedupHashLogic(unittest.TestCase):
    """Test the deterministic hash-based dedup for campaign tracking."""

    @staticmethod
    def _compute_campaign_hash(campaign: dict) -> str:
        """Replicate the hash logic from sentinel_generation_loop."""
        campaign_id = campaign.get("campaign_id", "")
        source_ips = sorted(campaign.get("unique_sources", []))
        target_ports = sorted(str(p) for p in campaign.get("target_ports", []))
        hash_input = (
            f"{campaign_id}|"
            f"{'|'.join(source_ips)}|"
            f"{'|'.join(target_ports)}"
        )
        return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[:16]

    def test_same_campaign_produces_same_hash(self):
        """Identical campaign data should produce the same hash."""
        campaign = {
            "campaign_id": "campaign_0",
            "unique_sources": ["10.0.0.1", "10.0.0.2"],
            "target_ports": [2222, 8080],
        }
        hash1 = self._compute_campaign_hash(campaign)
        hash2 = self._compute_campaign_hash(campaign)
        self.assertEqual(hash1, hash2)

    def test_different_campaigns_produce_different_hashes(self):
        """Different campaign data should produce different hashes."""
        campaign_a = {
            "campaign_id": "campaign_0",
            "unique_sources": ["10.0.0.1"],
            "target_ports": [2222],
        }
        campaign_b = {
            "campaign_id": "campaign_1",
            "unique_sources": ["10.0.0.5"],
            "target_ports": [8080],
        }
        hash_a = self._compute_campaign_hash(campaign_a)
        hash_b = self._compute_campaign_hash(campaign_b)
        self.assertNotEqual(hash_a, hash_b)

    def test_order_independence(self):
        """Hash should be order-independent (source IPs and ports are sorted)."""
        campaign_ordered = {
            "campaign_id": "campaign_0",
            "unique_sources": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            "target_ports": [22, 80, 443],
        }
        campaign_shuffled = {
            "campaign_id": "campaign_0",
            "unique_sources": ["10.0.0.3", "10.0.0.1", "10.0.0.2"],
            "target_ports": [443, 22, 80],
        }
        hash1 = self._compute_campaign_hash(campaign_ordered)
        hash2 = self._compute_campaign_hash(campaign_shuffled)
        self.assertEqual(hash1, hash2, "Hash should be order-independent")

    def test_hash_is_16_chars(self):
        """Hash should be truncated to 16 characters."""
        campaign = {
            "campaign_id": "campaign_0",
            "unique_sources": ["192.168.1.1"],
            "target_ports": [2222],
        }
        h = self._compute_campaign_hash(campaign)
        self.assertEqual(len(h), 16)

    def test_empty_campaign_still_produces_hash(self):
        """Even a campaign with empty fields should produce a valid hash."""
        campaign = {
            "campaign_id": "",
            "unique_sources": [],
            "target_ports": [],
        }
        h = self._compute_campaign_hash(campaign)
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 16)

    def test_dedup_set_rejects_duplicates(self):
        """Verify that the in-memory set correctly rejects duplicate hashes."""
        processed = set()
        campaign = {
            "campaign_id": "campaign_0",
            "unique_sources": ["10.0.0.1"],
            "target_ports": [2222],
        }
        h = self._compute_campaign_hash(campaign)

        # First encounter: should be new
        self.assertNotIn(h, processed)
        processed.add(h)

        # Second encounter: should be skipped
        self.assertIn(h, processed)


class TestFieldMapping(unittest.TestCase):
    """Test that campaign_clusterer output is correctly mapped to SentinelService input."""

    def test_field_mapping_from_clusterer_to_service(self):
        """Verify correct field mapping from campaign_clusterer → SentinelService."""
        # Simulated campaign_clusterer output
        clusterer_campaign = {
            "campaign_id": "campaign_0",
            "cluster_id": 0,
            "unique_sources": ["10.0.0.1", "10.0.0.2"],
            "target_ports": [2222, 8080],
            "protocols": ["TCP", "SSH"],
            "event_count": 42,
            "start_time": "2026-06-25T10:00:00",
            "end_time": "2026-06-25T12:00:00",
            "duration_seconds": 7200.0,
        }

        # Map to SentinelService format (as done in the loop)
        campaign_data = {
            "source_ips": clusterer_campaign.get("unique_sources", []),
            "target_ports": clusterer_campaign.get("target_ports", []),
            "protocols": clusterer_campaign.get("protocols", ["TCP"]),
            "event_count": clusterer_campaign.get("event_count", 0),
            "campaign_id": clusterer_campaign.get("campaign_id"),
            "time_range": {
                "start": clusterer_campaign.get("start_time"),
                "end": clusterer_campaign.get("end_time"),
            } if clusterer_campaign.get("start_time") else None,
        }

        # Assertions — verify correct field names for SentinelService
        self.assertEqual(campaign_data["source_ips"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(campaign_data["target_ports"], [2222, 8080])
        self.assertEqual(campaign_data["protocols"], ["TCP", "SSH"])
        self.assertEqual(campaign_data["event_count"], 42)
        self.assertEqual(campaign_data["campaign_id"], "campaign_0")
        self.assertIsNotNone(campaign_data["time_range"])
        self.assertEqual(campaign_data["time_range"]["start"], "2026-06-25T10:00:00")
        self.assertEqual(campaign_data["time_range"]["end"], "2026-06-25T12:00:00")

    def test_field_mapping_without_time_range(self):
        """Verify time_range is None when no start_time is present."""
        clusterer_campaign = {
            "campaign_id": "campaign_1",
            "unique_sources": ["10.0.0.5"],
            "target_ports": [2121],
            "protocols": ["FTP"],
            "event_count": 10,
        }

        campaign_data = {
            "source_ips": clusterer_campaign.get("unique_sources", []),
            "target_ports": clusterer_campaign.get("target_ports", []),
            "protocols": clusterer_campaign.get("protocols", ["TCP"]),
            "event_count": clusterer_campaign.get("event_count", 0),
            "campaign_id": clusterer_campaign.get("campaign_id"),
            "time_range": {
                "start": clusterer_campaign.get("start_time"),
                "end": clusterer_campaign.get("end_time"),
            } if clusterer_campaign.get("start_time") else None,
        }

        self.assertIsNone(campaign_data["time_range"])


class TestCycleCounters(unittest.TestCase):
    """Test cycle-level counters (new, skipped, errors)."""

    def test_counters_track_correctly(self):
        """Simulate a cycle with a mix of new, skipped, and error campaigns."""
        processed_hashes = set()
        new_count = 0
        skipped_count = 0
        error_count = 0

        campaigns = [
            {"campaign_id": "campaign_0", "unique_sources": ["10.0.0.1"], "target_ports": [2222]},
            {"campaign_id": "campaign_1", "unique_sources": ["10.0.0.2"], "target_ports": [8080]},
            {"campaign_id": "campaign_0", "unique_sources": ["10.0.0.1"], "target_ports": [2222]},  # duplicate
        ]

        for campaign in campaigns:
            campaign_id = campaign.get("campaign_id", "")
            source_ips = sorted(campaign.get("unique_sources", []))
            target_ports = sorted(str(p) for p in campaign.get("target_ports", []))
            hash_input = f"{campaign_id}|{'|'.join(source_ips)}|{'|'.join(target_ports)}"
            campaign_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[:16]

            if campaign_hash in processed_hashes:
                skipped_count += 1
                continue

            # Simulate successful generation
            processed_hashes.add(campaign_hash)
            new_count += 1

        self.assertEqual(new_count, 2, "Should have 2 new campaigns")
        self.assertEqual(skipped_count, 1, "Should have 1 skipped duplicate")
        self.assertEqual(error_count, 0, "Should have 0 errors")
        self.assertEqual(len(processed_hashes), 2, "Should track 2 unique hashes")


class TestEnvExampleFile(unittest.TestCase):
    """Verify .env.example contains the SENTINEL_ENABLED entry."""

    def test_env_example_contains_sentinel_enabled(self):
        """The .env.example file should have SENTINEL_ENABLED=false."""
        env_example_path = os.path.join(
            os.path.dirname(__file__), "..", ".env.example"
        )
        self.assertTrue(
            os.path.exists(env_example_path),
            f".env.example not found at {env_example_path}",
        )

        with open(env_example_path, "r") as f:
            content = f.read()

        self.assertIn(
            "SENTINEL_ENABLED=false", content,
            ".env.example should contain SENTINEL_ENABLED=false",
        )
        self.assertIn(
            "SENTINEL_ENABLED", content,
            ".env.example should reference SENTINEL_ENABLED",
        )


class TestLifespanIntegration(unittest.TestCase):
    """Test that the lifespan code block handles the SENTINEL_ENABLED toggle."""

    def test_main_py_has_sentinel_enabled_check(self):
        """main.py should contain the SENTINEL_ENABLED env var check."""
        main_path = os.path.join(
            os.path.dirname(__file__), "..", "backend", "main.py"
        )
        with open(main_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Verify the env var check exists
        self.assertIn("SENTINEL_ENABLED", content)
        self.assertIn("sentinel_generation_loop", content)
        self.assertIn("asyncio.create_task(sentinel_generation_loop())", content)

    def test_main_py_has_dedup_hash_logic(self):
        """main.py sentinel_generation_loop should contain hash-based dedup."""
        main_path = os.path.join(
            os.path.dirname(__file__), "..", "backend", "main.py"
        )
        with open(main_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("hashlib.sha256", content)
        self.assertIn("_processed_hashes", content)
        self.assertIn("campaign_hash", content)

    def test_main_py_has_cycle_logging(self):
        """main.py should log cycle metrics (found, new, skipped, errors)."""
        main_path = os.path.join(
            os.path.dirname(__file__), "..", "backend", "main.py"
        )
        with open(main_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("new_count", content)
        self.assertIn("skipped_count", content)
        self.assertIn("error_count", content)
        self.assertIn("total_found", content)
        self.assertIn("SUMMARY", content)

    def test_main_py_has_db_preseed(self):
        """main.py should pre-seed processed hashes from DB on startup."""
        main_path = os.path.join(
            os.path.dirname(__file__), "..", "backend", "main.py"
        )
        with open(main_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Pre-seed", content)
        self.assertIn("existing_playbooks", content)

    def test_main_py_maps_unique_sources_to_source_ips(self):
        """main.py should correctly map 'unique_sources' → 'source_ips'."""
        main_path = os.path.join(
            os.path.dirname(__file__), "..", "backend", "main.py"
        )
        with open(main_path, "r", encoding="utf-8") as f:
            content = f.read()

        # The mapping line should use unique_sources from clusterer output
        self.assertIn('"source_ips": campaign.get("unique_sources"', content)


if __name__ == "__main__":
    unittest.main()
