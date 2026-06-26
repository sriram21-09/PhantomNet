"""
tests/test_sentinel_service.py
-------------------------------
Day 5 — Comprehensive integration tests for SentinelService.

Verifies the full Sentinel pipeline:
  cluster → mitre_mapper → rule_generator → playbook_generator
  → stix_enhanced → DB save

Uses an in-memory SQLite database (mock) — does NOT touch production.

Phase 5, Week 2 (Week 14), Day 5
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import yaml

# ---------------------------------------------------------------------------
# Path setup — ensure backend/ is importable
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base, PacketLog, Event, IOC
from sentinel.models import SentinelPlaybook
from sentinel.sentinel_service import (
    SentinelService,
    _PORT_SERVICE_MAP,
    _SERVICE_DEFAULT_SIGNATURE,
    _generate_playbook_id,
)


# ---------------------------------------------------------------------------
# Test-only in-memory DB factory
# ---------------------------------------------------------------------------
def _make_test_session():
    """Create an in-memory SQLite engine + session with all tables."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    # Also create sentinel_playbooks table
    SentinelPlaybook.__table__.create(bind=engine, checkfirst=True)
    Session = sessionmaker(bind=engine)
    return Session(), engine


# ---------------------------------------------------------------------------
# Realistic mock campaign data matching campaign_clusterer output
# ---------------------------------------------------------------------------
CAMPAIGN_SSH_BRUTE = {
    "source_ips": ["10.0.0.1", "10.0.0.2"],
    "target_ports": [2222],
    "protocols": ["TCP", "SSH"],
    "event_count": 150,
    "campaign_id": "TEST-SSH-BF-001",
    "time_range": {
        "start": "2026-06-25T08:00:00",
        "end": "2026-06-25T12:00:00",
    },
}

CAMPAIGN_SQLI = {
    "source_ips": ["192.168.1.50"],
    "target_ports": [8080],
    "protocols": ["TCP"],
    "event_count": 85,
    "campaign_id": "TEST-SQLI-001",
    "time_range": {
        "start": "2026-06-25T14:00:00",
        "end": "2026-06-25T15:30:00",
    },
}

CAMPAIGN_PORT_SCAN = {
    "source_ips": ["172.16.0.10", "172.16.0.11"],
    "target_ports": [8080, 2222, 2121],
    "protocols": ["TCP", "UDP"],
    "event_count": 500,
    "campaign_id": "TEST-SCAN-001",
}


class TestSentinelServiceFullPipeline(unittest.TestCase):
    """Integration: full chain mock cluster → playbook → DB save."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _run_pipeline(self, campaign_data):
        svc = SentinelService(self.db)
        return svc.generate_playbook(campaign_data)

    # ------------------------------------------------------------------
    # 1. SSH brute force — full chain
    # ------------------------------------------------------------------
    def test_ssh_brute_force_full_chain(self):
        result = self._run_pipeline(CAMPAIGN_SSH_BRUTE)
        self.assertIsInstance(result, SentinelPlaybook)
        self.assertTrue(result.playbook_id.startswith("PB-"))
        self.assertEqual(result.status, "pending")
        self.assertIsNotNone(result.id)
        self.assertGreater(result.id, 0)

    # ------------------------------------------------------------------
    # 2. SQLi campaign — full chain
    # ------------------------------------------------------------------
    def test_sqli_full_chain(self):
        result = self._run_pipeline(CAMPAIGN_SQLI)
        self.assertIsInstance(result, SentinelPlaybook)
        self.assertTrue(result.playbook_id.startswith("PB-"))
        self.assertGreater(result.id, 0)

    # ------------------------------------------------------------------
    # 3. Port scan campaign — full chain
    # ------------------------------------------------------------------
    def test_port_scan_full_chain(self):
        result = self._run_pipeline(CAMPAIGN_PORT_SCAN)
        self.assertIsInstance(result, SentinelPlaybook)
        self.assertTrue(result.playbook_id.startswith("PB-"))
        self.assertGreater(result.id, 0)


class TestSentinelPlaybookFields(unittest.TestCase):
    """Verify SentinelPlaybook has all required fields populated."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        svc = SentinelService(cls.db)
        cls.result = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_core_identity_fields(self):
        r = self.result
        self.assertIsNotNone(r.id)
        self.assertIsNotNone(r.playbook_id)
        self.assertTrue(r.playbook_id.startswith("PB-"))
        self.assertIsNotNone(r.created_at)
        self.assertIsNotNone(r.updated_at)

    def test_threat_context_fields(self):
        r = self.result
        self.assertIsNotNone(r.src_ip)
        self.assertIn(r.src_ip, ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(r.dst_port, 2222)
        self.assertIsNotNone(r.protocol)
        self.assertIsNotNone(r.attack_type)
        self.assertIsInstance(r.threat_score, (int, float))

    def test_mitre_attack_fields(self):
        r = self.result
        self.assertIsNotNone(r.technique_id)
        self.assertTrue(r.technique_id.startswith("T"))
        self.assertIsNotNone(r.technique_name)
        self.assertIsNotNone(r.tactic)
        self.assertIsNotNone(r.mitre_url)
        self.assertIn("attack.mitre.org", r.mitre_url)

    def test_detection_rules_fields(self):
        r = self.result
        self.assertIsNotNone(r.snort_rule)
        self.assertGreater(len(r.snort_rule), 0)
        self.assertIsNotNone(r.sigma_rule)
        self.assertGreater(len(r.sigma_rule), 0)

    def test_playbook_content_fields(self):
        r = self.result
        self.assertIsNotNone(r.playbook_name)
        self.assertGreater(len(r.playbook_name), 0)
        self.assertIsNotNone(r.playbook_content)
        self.assertGreater(len(r.playbook_content), 0)

    def test_lifecycle_fields(self):
        r = self.result
        self.assertEqual(r.status, "pending")
        self.assertIsNone(r.reviewed_by)
        self.assertIsNone(r.reviewed_at)


class TestSnortRuleValidity(unittest.TestCase):
    """Verify snort_rules field contains valid Snort rule syntax."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        svc = SentinelService(cls.db)
        cls.ssh_result = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        cls.sqli_result = svc.generate_playbook(CAMPAIGN_SQLI)
        cls.scan_result = svc.generate_playbook(CAMPAIGN_PORT_SCAN)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _validate_snort(self, rule_text):
        self.assertIsNotNone(rule_text)
        self.assertGreater(len(rule_text), 0)
        for rule in rule_text.strip().split("\n"):
            rule = rule.strip()
            if not rule:
                continue
            self.assertTrue(
                rule.startswith("alert "),
                f"Snort rule must start with 'alert': {rule[:60]}",
            )
            self.assertIn("msg:", rule)
            self.assertIn("sid:", rule)
            self.assertIn("rev:", rule)
            self.assertTrue(rule.endswith(")"), f"Snort rule must end with ')': {rule[-30:]}")

    def test_ssh_snort_rule_valid(self):
        self._validate_snort(self.ssh_result.snort_rule)

    def test_sqli_snort_rule_valid(self):
        self._validate_snort(self.sqli_result.snort_rule)

    def test_scan_snort_rule_valid(self):
        self._validate_snort(self.scan_result.snort_rule)

    def test_snort_rule_has_protocol(self):
        rule = self.ssh_result.snort_rule.split("\n")[0]
        parts = rule.split()
        self.assertIn(parts[1], ["tcp", "udp", "icmp", "ip"])

    def test_snort_rule_has_mitre_reference(self):
        self.assertIn("attack.mitre.org", self.ssh_result.snort_rule)


class TestSigmaRuleValidity(unittest.TestCase):
    """Verify sigma_rules field contains valid Sigma YAML."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        svc = SentinelService(cls.db)
        cls.ssh_result = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        cls.sqli_result = svc.generate_playbook(CAMPAIGN_SQLI)
        cls.scan_result = svc.generate_playbook(CAMPAIGN_PORT_SCAN)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _validate_sigma(self, sigma_text):
        self.assertIsNotNone(sigma_text)
        self.assertGreater(len(sigma_text), 0)
        # Sigma rules may be separated by '---'
        docs = sigma_text.split("---")
        for doc in docs:
            doc = doc.strip()
            if not doc:
                continue
            parsed = yaml.safe_load(doc)
            self.assertIsInstance(parsed, dict)
            self.assertIn("title", parsed)
            self.assertIn("logsource", parsed)
            self.assertIn("detection", parsed)
            self.assertIn("level", parsed)
            self.assertIn(parsed["level"], ["critical", "high", "medium", "low"])

    def test_ssh_sigma_rule_valid(self):
        self._validate_sigma(self.ssh_result.sigma_rule)

    def test_sqli_sigma_rule_valid(self):
        self._validate_sigma(self.sqli_result.sigma_rule)

    def test_scan_sigma_rule_valid(self):
        self._validate_sigma(self.scan_result.sigma_rule)

    def test_sigma_has_condition(self):
        doc = yaml.safe_load(self.ssh_result.sigma_rule.split("---")[0])
        self.assertIn("condition", doc["detection"])


class TestStixBundleValidity(unittest.TestCase):
    """Verify stix_bundle field contains valid STIX JSON."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        svc = SentinelService(cls.db)
        cls.result = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        cls.rd = cls.result.result_dict

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_stix_json_parseable(self):
        stix_json = self.rd["stix_bundle_json"]
        self.assertIsNotNone(stix_json)
        bundle = json.loads(stix_json)
        self.assertIsInstance(bundle, dict)

    def test_stix_bundle_type(self):
        bundle = json.loads(self.rd["stix_bundle_json"])
        self.assertEqual(bundle["type"], "bundle")

    def test_stix_bundle_has_objects(self):
        bundle = json.loads(self.rd["stix_bundle_json"])
        self.assertIn("objects", bundle)
        self.assertIsInstance(bundle["objects"], list)
        self.assertGreater(len(bundle["objects"]), 0)

    def test_stix_has_identity(self):
        bundle = json.loads(self.rd["stix_bundle_json"])
        types = [obj["type"] for obj in bundle["objects"]]
        self.assertIn("identity", types)

    def test_stix_has_attack_pattern(self):
        bundle = json.loads(self.rd["stix_bundle_json"])
        types = [obj["type"] for obj in bundle["objects"]]
        self.assertIn("attack-pattern", types)

    def test_stix_has_indicator(self):
        bundle = json.loads(self.rd["stix_bundle_json"])
        types = [obj["type"] for obj in bundle["objects"]]
        self.assertIn("indicator", types)

    def test_stix_has_relationship(self):
        bundle = json.loads(self.rd["stix_bundle_json"])
        types = [obj["type"] for obj in bundle["objects"]]
        self.assertIn("relationship", types)

    def test_stix_attack_pattern_has_mitre_ref(self):
        bundle = json.loads(self.rd["stix_bundle_json"])
        ap = [o for o in bundle["objects"] if o["type"] == "attack-pattern"][0]
        ext_refs = ap.get("external_references", [])
        mitre_refs = [r for r in ext_refs if r.get("source_name") == "mitre-attack"]
        self.assertGreater(len(mitre_refs), 0)


class TestPlaybookContentValidity(unittest.TestCase):
    """Verify playbook_content field contains valid Markdown."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        svc = SentinelService(cls.db)
        cls.ssh = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        cls.sqli = svc.generate_playbook(CAMPAIGN_SQLI)
        cls.scan = svc.generate_playbook(CAMPAIGN_PORT_SCAN)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_ssh_playbook_is_markdown(self):
        content = self.ssh.playbook_content
        self.assertIsNotNone(content)
        self.assertTrue(content.strip().startswith("#"))

    def test_sqli_playbook_is_markdown(self):
        content = self.sqli.playbook_content
        self.assertIsNotNone(content)
        self.assertTrue(content.strip().startswith("#"))

    def test_scan_playbook_is_markdown(self):
        content = self.scan.playbook_content
        self.assertIsNotNone(content)
        self.assertTrue(content.strip().startswith("#"))

    def test_playbook_has_campaign_id(self):
        # Campaign ID is always in result_dict; templates may or may not embed it
        self.assertEqual(self.ssh.result_dict["campaign_id"], "TEST-SSH-BF-001")
        # Playbook content should be substantive Markdown
        self.assertGreater(len(self.ssh.playbook_content), 50)

    def test_playbook_has_technique_info(self):
        content = self.ssh.playbook_content
        self.assertIn("T1", content)


class TestMultipleAttackTypes(unittest.TestCase):
    """Test pipeline with SSH brute force, SQLi, and port scan."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        svc = SentinelService(cls.db)
        cls.ssh = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        cls.sqli = svc.generate_playbook(CAMPAIGN_SQLI)
        cls.scan = svc.generate_playbook(CAMPAIGN_PORT_SCAN)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_ssh_service_type(self):
        self.assertEqual(self.ssh.result_dict["service_type"], "SSH")

    def test_sqli_service_type(self):
        self.assertEqual(self.sqli.result_dict["service_type"], "HTTP")

    def test_scan_service_type(self):
        # First recognised port is 8080 → HTTP
        self.assertIn(self.scan.result_dict["service_type"], ["HTTP", "SSH", "FTP"])

    def test_all_have_unique_playbook_ids(self):
        ids = {self.ssh.playbook_id, self.sqli.playbook_id, self.scan.playbook_id}
        self.assertEqual(len(ids), 3)

    def test_all_have_snort_rules(self):
        for r in [self.ssh, self.sqli, self.scan]:
            self.assertIsNotNone(r.snort_rule)
            self.assertGreater(len(r.snort_rule), 0)

    def test_all_have_sigma_rules(self):
        for r in [self.ssh, self.sqli, self.scan]:
            self.assertIsNotNone(r.sigma_rule)
            self.assertGreater(len(r.sigma_rule), 0)

    def test_all_have_playbook_content(self):
        for r in [self.ssh, self.sqli, self.scan]:
            self.assertIsNotNone(r.playbook_content)
            self.assertGreater(len(r.playbook_content), 0)

    def test_all_have_stix_bundles(self):
        for r in [self.ssh, self.sqli, self.scan]:
            stix = r.result_dict["stix_bundle_json"]
            self.assertIsNotNone(stix)
            bundle = json.loads(stix)
            self.assertEqual(bundle["type"], "bundle")


class TestDBSave(unittest.TestCase):
    """Verify DB save completes without errors."""

    def setUp(self):
        self.db, self.engine = _make_test_session()

    def tearDown(self):
        self.db.close()

    def test_db_save_ssh(self):
        svc = SentinelService(self.db)
        result = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        row = self.db.query(SentinelPlaybook).filter_by(
            playbook_id=result.playbook_id
        ).first()
        self.assertIsNotNone(row)
        self.assertEqual(row.status, "pending")
        self.assertGreater(row.id, 0)

    def test_db_save_sqli(self):
        svc = SentinelService(self.db)
        result = svc.generate_playbook(CAMPAIGN_SQLI)
        row = self.db.query(SentinelPlaybook).filter_by(
            playbook_id=result.playbook_id
        ).first()
        self.assertIsNotNone(row)
        self.assertGreater(row.id, 0)

    def test_db_save_scan(self):
        svc = SentinelService(self.db)
        result = svc.generate_playbook(CAMPAIGN_PORT_SCAN)
        row = self.db.query(SentinelPlaybook).filter_by(
            playbook_id=result.playbook_id
        ).first()
        self.assertIsNotNone(row)
        self.assertGreater(row.id, 0)

    def test_db_row_has_all_columns(self):
        svc = SentinelService(self.db)
        result = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        row = self.db.query(SentinelPlaybook).filter_by(
            playbook_id=result.playbook_id
        ).first()
        self.assertIsNotNone(row.playbook_id)
        self.assertIsNotNone(row.src_ip)
        self.assertIsNotNone(row.dst_port)
        self.assertIsNotNone(row.protocol)
        self.assertIsNotNone(row.attack_type)
        self.assertIsNotNone(row.technique_id)
        self.assertIsNotNone(row.technique_name)
        self.assertIsNotNone(row.tactic)
        self.assertIsNotNone(row.mitre_url)
        self.assertIsNotNone(row.snort_rule)
        self.assertIsNotNone(row.sigma_rule)
        self.assertIsNotNone(row.playbook_name)
        self.assertIsNotNone(row.playbook_content)
        self.assertEqual(row.status, "pending")

    def test_db_to_dict_serialization(self):
        svc = SentinelService(self.db)
        result = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        d = result.to_dict()
        self.assertIsInstance(d, dict)
        expected_keys = [
            "id", "playbook_id", "created_at", "updated_at",
            "src_ip", "dst_port", "protocol", "attack_type", "threat_score",
            "technique_id", "technique_name", "tactic", "mitre_url",
            "snort_rule", "sigma_rule",
            "playbook_name", "playbook_content", "template_name",
            "status", "reviewed_by", "reviewed_at",
        ]
        for key in expected_keys:
            self.assertIn(key, d, f"Missing key in to_dict(): {key}")

    def test_multiple_saves_no_collision(self):
        svc = SentinelService(self.db)
        r1 = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        r2 = svc.generate_playbook(CAMPAIGN_SQLI)
        r3 = svc.generate_playbook(CAMPAIGN_PORT_SCAN)
        count = self.db.query(SentinelPlaybook).count()
        self.assertGreaterEqual(count, 3)
        self.assertNotEqual(r1.playbook_id, r2.playbook_id)
        self.assertNotEqual(r2.playbook_id, r3.playbook_id)


class TestResultDictArtefacts(unittest.TestCase):
    """Verify result_dict carries all generated artefacts."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        svc = SentinelService(cls.db)
        cls.result = svc.generate_playbook(CAMPAIGN_SSH_BRUTE)
        cls.rd = cls.result.result_dict

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_result_dict_has_playbook_id(self):
        self.assertTrue(self.rd["playbook_id"].startswith("PB-"))

    def test_result_dict_has_campaign_id(self):
        self.assertEqual(self.rd["campaign_id"], "TEST-SSH-BF-001")

    def test_result_dict_has_service_type(self):
        self.assertEqual(self.rd["service_type"], "SSH")

    def test_result_dict_has_technique(self):
        t = self.rd["technique"]
        self.assertIsNotNone(t["id"])
        self.assertIsNotNone(t["name"])
        self.assertIsNotNone(t["tactic"])

    def test_result_dict_has_snort_rule(self):
        self.assertIsNotNone(self.rd["snort_rule"])
        self.assertGreater(len(self.rd["snort_rule"]), 0)

    def test_result_dict_has_sigma_rule(self):
        self.assertIsNotNone(self.rd["sigma_rule"])
        self.assertGreater(len(self.rd["sigma_rule"]), 0)

    def test_result_dict_has_stix_bundle(self):
        self.assertIsNotNone(self.rd["stix_bundle_json"])
        bundle = json.loads(self.rd["stix_bundle_json"])
        self.assertEqual(bundle["type"], "bundle")

    def test_result_dict_has_playbook_content(self):
        self.assertIsNotNone(self.rd["playbook_content"])
        self.assertGreater(len(self.rd["playbook_content"]), 0)

    def test_result_dict_has_db_record_id(self):
        self.assertGreater(self.rd["db_record_id"], 0)

    def test_result_dict_has_enrichment_fields(self):
        self.assertIn("ioc_count", self.rd)
        self.assertIn("ioc_threat_level", self.rd)
        self.assertIn("matched_logs_count", self.rd)
        self.assertIn("signatures_stored_count", self.rd)
        self.assertIn("detected_signatures", self.rd)


if __name__ == "__main__":
    unittest.main()
