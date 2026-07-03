"""
tests/test_week15_day2_bugfix_validation.py
---------------------------------------------
Week 15, Day 2 — Bug-fix validation across all 3 E2E scenarios.

Verifies that all pipeline bugs from Day 11 are resolved:
  - Data flow: campaign cluster → sentinel_service correctly
  - Missing fields: all 23 SentinelPlaybook columns populated
  - DB save: records persist without failures
  - All 3 scenarios (SSH brute force, SQLi, port scan) produce correct output
  - Edge cases handled gracefully

Phase 5, Week 3 (Week 15), Day 2
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base, PacketLog, Event, IOC
from sentinel.models import SentinelPlaybook
from sentinel.sentinel_service import SentinelService


def _make_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SentinelPlaybook.__table__.create(bind=engine, checkfirst=True)
    return sessionmaker(bind=engine)(), engine


BT = datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc)

SSH_CAMP = {
    "source_ips": ["10.0.0.1", "10.0.0.2"],
    "target_ports": [2222],
    "protocols": ["TCP", "SSH"],
    "event_count": 150,
    "campaign_id": "TEST-SSH-BF-001",
    "time_range": {"start": BT.isoformat(), "end": (BT + timedelta(hours=4)).isoformat()},
}

SQLI_CAMP = {
    "source_ips": ["192.168.1.50"],
    "target_ports": [8080],
    "protocols": ["TCP"],
    "event_count": 85,
    "campaign_id": "TEST-SQLI-001",
    "time_range": {"start": BT.isoformat(), "end": (BT + timedelta(hours=2)).isoformat()},
}

SCAN_CAMP = {
    "source_ips": ["172.16.0.10", "172.16.0.11"],
    "target_ports": [8080, 2222, 2121],
    "protocols": ["TCP", "UDP"],
    "event_count": 500,
    "campaign_id": "TEST-SCAN-001",
}


def _seed_data(db):
    """Inject realistic test data for all 3 scenarios."""
    # SSH brute force
    for i in range(30):
        db.add(PacketLog(
            timestamp=BT + timedelta(seconds=i * 5),
            src_ip=["10.0.0.1", "10.0.0.2"][i % 2],
            dst_ip="10.0.0.50", src_port=40000 + i, dst_port=2222,
            protocol="TCP", length=128, attack_type="SSH_AUTH_FAILURE",
            threat_score=70.0 + (i % 20), threat_level="High",
            confidence=0.8, is_malicious=True,
        ))
    for i in range(10):
        db.add(Event(
            source_ip=["10.0.0.1", "10.0.0.2"][i % 2],
            src_port=40000 + i, honeypot_type="SSH",
            raw_data="SSH-2.0-OpenSSH_7.4\r\nFailed password for root",
            timestamp=BT + timedelta(seconds=i * 8),
        ))
    # SQLi
    for i in range(30):
        db.add(PacketLog(
            timestamp=BT + timedelta(seconds=i * 5),
            src_ip="192.168.1.50", dst_ip="10.0.0.60",
            src_port=50000 + i, dst_port=8080,
            protocol="TCP", length=256, attack_type="HTTP_SCANNER_BEHAVIOR",
            threat_score=60.0 + (i % 20), threat_level="Medium",
            confidence=0.7, is_malicious=True,
        ))
    for i in range(10):
        db.add(Event(
            source_ip="192.168.1.50", src_port=50000 + i,
            honeypot_type="HTTP",
            raw_data="GET /login?user=admin' OR 1=1-- HTTP/1.1",
            timestamp=BT + timedelta(seconds=i * 8),
        ))
    # Port scan
    for i in range(30):
        db.add(PacketLog(
            timestamp=BT + timedelta(seconds=i * 5),
            src_ip=["172.16.0.10", "172.16.0.11"][i % 2],
            dst_ip="10.0.0.70", src_port=60000 + i,
            dst_port=[8080, 2222, 2121][i % 3],
            protocol="TCP", length=64, attack_type="PORT_SCAN",
            threat_score=50.0 + (i % 20), threat_level="Medium",
            confidence=0.6, is_malicious=True,
        ))
    # IOCs
    for ip in ["10.0.0.1", "10.0.0.2", "192.168.1.50", "172.16.0.10", "172.16.0.11"]:
        db.add(IOC(type="IP", value=ip, description="test", threat_level="High", is_watchlist=True))
    db.commit()


class TestAllThreeScenariosDataFlow(unittest.TestCase):
    """Verify campaign data flows correctly into sentinel for all 3 scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_session()
        _seed_data(cls.db)
        svc = SentinelService(cls.db)
        cls.ssh = svc.generate_playbook(SSH_CAMP)
        cls.sqli = svc.generate_playbook(SQLI_CAMP)
        cls.scan = svc.generate_playbook(SCAN_CAMP)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    # --- SSH ---
    def test_ssh_service_type(self):
        self.assertEqual(self.ssh.result_dict["service_type"], "SSH")

    def test_ssh_src_ip_flows(self):
        self.assertIn(self.ssh.src_ip, SSH_CAMP["source_ips"])

    def test_ssh_dst_port_flows(self):
        self.assertEqual(self.ssh.dst_port, 2222)

    def test_ssh_campaign_id_flows(self):
        self.assertEqual(self.ssh.result_dict["campaign_id"], "TEST-SSH-BF-001")

    def test_ssh_matched_logs(self):
        self.assertGreater(self.ssh.result_dict["matched_logs_count"], 0)

    # --- SQLi ---
    def test_sqli_service_type(self):
        self.assertEqual(self.sqli.result_dict["service_type"], "HTTP")

    def test_sqli_src_ip_flows(self):
        self.assertEqual(self.sqli.src_ip, "192.168.1.50")

    def test_sqli_dst_port_flows(self):
        self.assertEqual(self.sqli.dst_port, 8080)

    def test_sqli_campaign_id_flows(self):
        self.assertEqual(self.sqli.result_dict["campaign_id"], "TEST-SQLI-001")

    def test_sqli_matched_logs(self):
        self.assertGreater(self.sqli.result_dict["matched_logs_count"], 0)

    # --- Port Scan ---
    def test_scan_service_type(self):
        self.assertIn(self.scan.result_dict["service_type"], ["HTTP", "SSH", "FTP"])

    def test_scan_src_ip_flows(self):
        self.assertIn(self.scan.src_ip, SCAN_CAMP["source_ips"])

    def test_scan_dst_port_flows(self):
        self.assertIn(self.scan.dst_port, SCAN_CAMP["target_ports"])

    def test_scan_campaign_id_flows(self):
        self.assertEqual(self.scan.result_dict["campaign_id"], "TEST-SCAN-001")

    def test_scan_matched_logs(self):
        self.assertGreater(self.scan.result_dict["matched_logs_count"], 0)


class TestAll23ColumnsPopulated(unittest.TestCase):
    """Verify all 23 SentinelPlaybook columns are populated for each scenario."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_session()
        _seed_data(cls.db)
        svc = SentinelService(cls.db)
        cls.results = {
            "SSH": svc.generate_playbook(SSH_CAMP),
            "SQLi": svc.generate_playbook(SQLI_CAMP),
            "Scan": svc.generate_playbook(SCAN_CAMP),
        }

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _check_columns(self, r, label):
        self.assertIsNotNone(r.id, f"{label}: id is None")
        self.assertGreater(r.id, 0, f"{label}: id <= 0")
        self.assertTrue(r.playbook_id.startswith("PB-"), f"{label}: bad playbook_id")
        self.assertIsNotNone(r.created_at, f"{label}: created_at None")
        self.assertIsNotNone(r.updated_at, f"{label}: updated_at None")
        self.assertIsNotNone(r.src_ip, f"{label}: src_ip None")
        self.assertIsNotNone(r.dst_port, f"{label}: dst_port None")
        self.assertIsNotNone(r.protocol, f"{label}: protocol None")
        self.assertIsNotNone(r.attack_type, f"{label}: attack_type None")
        self.assertIsInstance(r.threat_score, (int, float), f"{label}: threat_score bad type")
        self.assertIsInstance(r.confidence_score, (int, float), f"{label}: confidence_score bad type")
        self.assertIn(r.severity, ["CRITICAL", "HIGH", "MEDIUM", "LOW"], f"{label}: bad severity")
        self.assertTrue(r.technique_id.startswith("T"), f"{label}: bad technique_id")
        self.assertGreater(len(r.technique_name), 0, f"{label}: empty technique_name")
        self.assertGreater(len(r.tactic), 0, f"{label}: empty tactic")
        self.assertIn("attack.mitre.org", r.mitre_url, f"{label}: bad mitre_url")
        self.assertGreater(len(r.snort_rule), 0, f"{label}: empty snort_rule")
        self.assertGreater(len(r.sigma_rule), 0, f"{label}: empty sigma_rule")
        self.assertGreater(len(r.playbook_name), 0, f"{label}: empty playbook_name")
        self.assertGreater(len(r.playbook_content), 100, f"{label}: short playbook_content")
        self.assertIsNotNone(r.template_name, f"{label}: template_name None")
        self.assertEqual(r.status, "pending", f"{label}: bad status")
        self.assertIsNone(r.reviewed_by, f"{label}: reviewed_by not None")
        self.assertIsNone(r.reviewed_at, f"{label}: reviewed_at not None")

    def test_ssh_all_23_columns(self):
        self._check_columns(self.results["SSH"], "SSH")

    def test_sqli_all_23_columns(self):
        self._check_columns(self.results["SQLi"], "SQLi")

    def test_scan_all_23_columns(self):
        self._check_columns(self.results["Scan"], "Scan")

    def test_to_dict_has_23_keys(self):
        for label, r in self.results.items():
            d = r.to_dict()
            self.assertEqual(len(d), 23, f"{label}: to_dict has {len(d)} keys, expected 23")


class TestDBSaveNoFailures(unittest.TestCase):
    """Verify all 3 scenarios persist to DB without failures."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_session()
        _seed_data(cls.db)
        svc = SentinelService(cls.db)
        cls.ssh = svc.generate_playbook(SSH_CAMP)
        cls.sqli = svc.generate_playbook(SQLI_CAMP)
        cls.scan = svc.generate_playbook(SCAN_CAMP)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_ssh_persisted(self):
        row = self.db.query(SentinelPlaybook).filter_by(playbook_id=self.ssh.playbook_id).first()
        self.assertIsNotNone(row)
        self.assertEqual(row.technique_id, self.ssh.technique_id)

    def test_sqli_persisted(self):
        row = self.db.query(SentinelPlaybook).filter_by(playbook_id=self.sqli.playbook_id).first()
        self.assertIsNotNone(row)
        self.assertEqual(row.technique_id, self.sqli.technique_id)

    def test_scan_persisted(self):
        row = self.db.query(SentinelPlaybook).filter_by(playbook_id=self.scan.playbook_id).first()
        self.assertIsNotNone(row)
        self.assertEqual(row.technique_id, self.scan.technique_id)

    def test_total_rows(self):
        count = self.db.query(SentinelPlaybook).count()
        self.assertGreaterEqual(count, 3)

    def test_unique_ids(self):
        ids = {self.ssh.playbook_id, self.sqli.playbook_id, self.scan.playbook_id}
        self.assertEqual(len(ids), 3)

    def test_db_roundtrip_serialization(self):
        for r in [self.ssh, self.sqli, self.scan]:
            d = r.to_dict()
            self.assertIsInstance(d, dict)
            self.assertIn("playbook_id", d)
            self.assertIn("technique_id", d)


class TestSnortRulesAllScenarios(unittest.TestCase):
    """Verify Snort rule quality for all 3 scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_session()
        _seed_data(cls.db)
        svc = SentinelService(cls.db)
        cls.ssh = svc.generate_playbook(SSH_CAMP)
        cls.sqli = svc.generate_playbook(SQLI_CAMP)
        cls.scan = svc.generate_playbook(SCAN_CAMP)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _check_snort(self, r, label):
        rule = r.snort_rule.split("\n")[0].strip()
        self.assertTrue(rule.startswith("alert "), f"{label}: not alert rule")
        self.assertIn("msg:", rule, f"{label}: missing msg")
        self.assertIn("sid:", rule, f"{label}: missing sid")
        self.assertIn("rev:", rule, f"{label}: missing rev")
        self.assertTrue(rule.endswith(")"), f"{label}: not ending with )")
        self.assertIn("flow:", rule, f"{label}: missing flow")
        self.assertIn("classtype:", rule, f"{label}: missing classtype")
        self.assertIn("attack.mitre.org", rule, f"{label}: missing MITRE ref")

    def test_ssh_snort(self):
        self._check_snort(self.ssh, "SSH")

    def test_sqli_snort(self):
        self._check_snort(self.sqli, "SQLi")

    def test_scan_snort(self):
        self._check_snort(self.scan, "Scan")


class TestSigmaRulesAllScenarios(unittest.TestCase):
    """Verify Sigma rule quality for all 3 scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_session()
        _seed_data(cls.db)
        svc = SentinelService(cls.db)
        cls.ssh = svc.generate_playbook(SSH_CAMP)
        cls.sqli = svc.generate_playbook(SQLI_CAMP)
        cls.scan = svc.generate_playbook(SCAN_CAMP)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _check_sigma(self, r, label):
        doc = yaml.safe_load(r.sigma_rule.split("---")[0].strip())
        self.assertIsInstance(doc, dict, f"{label}: not a dict")
        self.assertIn("title", doc, f"{label}: missing title")
        self.assertIn("logsource", doc, f"{label}: missing logsource")
        self.assertEqual(doc["logsource"]["category"], "network_traffic", f"{label}: bad category")
        self.assertEqual(doc["logsource"]["product"], "phantomnet", f"{label}: bad product")
        self.assertIn("detection", doc, f"{label}: missing detection")
        self.assertIn("selection", doc["detection"], f"{label}: missing selection")
        self.assertIn("condition", doc["detection"], f"{label}: missing condition")
        self.assertIn("level", doc, f"{label}: missing level")
        self.assertIn(doc["level"], ["critical", "high", "medium", "low"], f"{label}: bad level")

    def test_ssh_sigma(self):
        self._check_sigma(self.ssh, "SSH")

    def test_sqli_sigma(self):
        self._check_sigma(self.sqli, "SQLi")

    def test_scan_sigma(self):
        self._check_sigma(self.scan, "Scan")


class TestStixBundlesAllScenarios(unittest.TestCase):
    """Verify STIX bundle quality for all 3 scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_session()
        _seed_data(cls.db)
        svc = SentinelService(cls.db)
        cls.ssh = svc.generate_playbook(SSH_CAMP)
        cls.sqli = svc.generate_playbook(SQLI_CAMP)
        cls.scan = svc.generate_playbook(SCAN_CAMP)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _check_stix(self, r, label):
        bundle = json.loads(r.result_dict["stix_bundle_json"])
        self.assertEqual(bundle["type"], "bundle", f"{label}: not bundle")
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("identity", types, f"{label}: missing identity")
        self.assertIn("attack-pattern", types, f"{label}: missing attack-pattern")
        self.assertIn("indicator", types, f"{label}: missing indicator")
        self.assertIn("relationship", types, f"{label}: missing relationship")
        aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        ext = aps[0].get("external_references", [])
        mitre = [e for e in ext if e.get("source_name") == "mitre-attack"]
        self.assertGreater(len(mitre), 0, f"{label}: no mitre ref")
        self.assertEqual(mitre[0]["external_id"], r.technique_id, f"{label}: ID mismatch")

    def test_ssh_stix(self):
        self._check_stix(self.ssh, "SSH")

    def test_sqli_stix(self):
        self._check_stix(self.sqli, "SQLi")

    def test_scan_stix(self):
        self._check_stix(self.scan, "Scan")


class TestPlaybookMarkdownAllScenarios(unittest.TestCase):
    """Verify playbook Markdown quality for all 3 scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_session()
        _seed_data(cls.db)
        svc = SentinelService(cls.db)
        cls.ssh = svc.generate_playbook(SSH_CAMP)
        cls.sqli = svc.generate_playbook(SQLI_CAMP)
        cls.scan = svc.generate_playbook(SCAN_CAMP)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _check_playbook(self, r, camp, label):
        c = r.playbook_content
        self.assertTrue(c.strip().startswith("#"), f"{label}: no header")
        self.assertIn("Severity", c, f"{label}: missing Severity")
        self.assertIn(camp["source_ips"][0], c, f"{label}: missing source IP")
        self.assertIn("T1", c, f"{label}: missing technique ref")
        self.assertGreater(len(c), 200, f"{label}: content too short")

    def test_ssh_playbook(self):
        self._check_playbook(self.ssh, SSH_CAMP, "SSH")

    def test_sqli_playbook(self):
        self._check_playbook(self.sqli, SQLI_CAMP, "SQLi")

    def test_scan_playbook(self):
        self._check_playbook(self.scan, SCAN_CAMP, "Scan")


class TestEdgeCases(unittest.TestCase):
    """Verify pipeline handles edge cases without crashing."""

    def setUp(self):
        self.db, self.engine = _make_session()

    def tearDown(self):
        self.db.close()

    def test_empty_campaign(self):
        svc = SentinelService(self.db)
        r = svc.generate_playbook({
            "source_ips": [], "target_ports": [],
            "protocols": ["TCP"], "event_count": 0,
        })
        self.assertIsInstance(r, SentinelPlaybook)
        self.assertIsNotNone(r.technique_id)

    def test_single_ip(self):
        svc = SentinelService(self.db)
        r = svc.generate_playbook({
            "source_ips": ["1.2.3.4"], "target_ports": [2222],
            "protocols": ["TCP"], "event_count": 1,
            "campaign_id": "EDGE-SINGLE",
        })
        self.assertIsInstance(r, SentinelPlaybook)
        self.assertEqual(r.src_ip, "1.2.3.4")

    def test_unknown_port(self):
        svc = SentinelService(self.db)
        r = svc.generate_playbook({
            "source_ips": ["5.6.7.8"], "target_ports": [9999],
            "protocols": ["TCP"], "event_count": 10,
            "campaign_id": "EDGE-UNKNOWNPORT",
        })
        self.assertIsInstance(r, SentinelPlaybook)
        self.assertIsNotNone(r.playbook_content)

    def test_no_time_range(self):
        svc = SentinelService(self.db)
        r = svc.generate_playbook({
            "source_ips": ["9.8.7.6"], "target_ports": [8080],
            "protocols": ["TCP"], "event_count": 5,
        })
        self.assertIsInstance(r, SentinelPlaybook)


if __name__ == "__main__":
    unittest.main()
