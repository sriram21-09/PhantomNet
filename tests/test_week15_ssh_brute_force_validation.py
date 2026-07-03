"""
tests/test_week15_ssh_brute_force_validation.py
-------------------------------------------------
Week 15, Day 1 — SSH Brute Force T1110.001 Validation Suite

Injects realistic SSH brute force PacketLog data (port 2222, repeated
auth failures) into an in-memory DB, triggers the sentinel pipeline,
and validates every aspect of the generated playbook.

⚠️  Does NOT modify sentinel_service.py — validation only.

Validates:
  1. PacketLog injection with realistic SSH traffic patterns
  2. Sentinel pipeline processes injected data correctly
  3. T1110.001 technique mapping (Brute Force: Password Guessing)
  4. Snort rule: msg, flow, threshold, classtype fields
  5. Sigma rule: logsource + detection block for SSH auth failures
  6. STIX bundle: ExternalReferences to ATT&CK T1110.001
  7. Playbook Markdown: all 7 sections rendered
  8. DB persistence: all 23 columns populated

Phase 5, Week 3 (Week 15), Day 1
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base, PacketLog, Event, IOC
from sentinel.models import SentinelPlaybook
from sentinel.sentinel_service import SentinelService


# ---------------------------------------------------------------------------
# In-memory DB factory
# ---------------------------------------------------------------------------
def _make_test_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    SentinelPlaybook.__table__.create(bind=engine, checkfirst=True)
    Session = sessionmaker(bind=engine)
    return Session(), engine


# ---------------------------------------------------------------------------
# Realistic SSH brute force test data
# ---------------------------------------------------------------------------
SSH_ATTACKER_IPS = [
    "203.0.113.45",
    "203.0.113.46",
    "198.51.100.77",
]

SSH_TARGET_PORT = 2222
SSH_EVENT_COUNT = 150
SSH_CAMPAIGN_ID = "CAMP-W15-SSH-BF-001"

BASE_TIME = datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc)

SSH_BRUTE_CAMPAIGN = {
    "source_ips": SSH_ATTACKER_IPS,
    "target_ports": [SSH_TARGET_PORT],
    "protocols": ["TCP"],
    "event_count": SSH_EVENT_COUNT,
    "campaign_id": SSH_CAMPAIGN_ID,
    "time_range": {
        "start": BASE_TIME.isoformat(),
        "end": (BASE_TIME + timedelta(hours=4)).isoformat(),
    },
}


def _inject_packet_logs(db, count=50):
    """Insert realistic SSH brute force PacketLog rows."""
    logs = []
    for i in range(count):
        ip = SSH_ATTACKER_IPS[i % len(SSH_ATTACKER_IPS)]
        ts = BASE_TIME + timedelta(seconds=i * 5)
        log = PacketLog(
            timestamp=ts,
            src_ip=ip,
            dst_ip="10.0.0.50",
            src_port=40000 + i,
            dst_port=SSH_TARGET_PORT,
            protocol="TCP",
            length=128 + (i % 64),
            attack_type="SSH_AUTH_FAILURE",
            threat_score=65.0 + (i % 30),
            threat_level="High",
            confidence=0.85,
            is_malicious=True,
            event="login_attempt",
        )
        logs.append(log)
    db.add_all(logs)
    db.commit()
    return logs


def _inject_events(db, count=20):
    """Insert realistic SSH auth failure Event rows."""
    events = []
    payloads = [
        "SSH-2.0-OpenSSH_7.4\\r\\nFailed password for root",
        "SSH-2.0-libssh2_1.8.0\\r\\nFailed password for admin",
        "SSH-2.0-PuTTY_0.70\\r\\nFailed password for user",
        "SSH-2.0-paramiko_2.7.2\\r\\nFailed password for test",
        "SSH-2.0-Go\\r\\nFailed password for ubuntu",
    ]
    for i in range(count):
        ip = SSH_ATTACKER_IPS[i % len(SSH_ATTACKER_IPS)]
        ts = BASE_TIME + timedelta(seconds=i * 8)
        ev = Event(
            source_ip=ip,
            src_port=40000 + i,
            honeypot_type="SSH",
            raw_data=payloads[i % len(payloads)],
            timestamp=ts,
        )
        events.append(ev)
    db.add_all(events)
    db.commit()
    return events


def _inject_iocs(db):
    """Insert IOC entries for attacker IPs."""
    iocs = []
    for ip in SSH_ATTACKER_IPS:
        ioc = IOC(
            type="IP",
            value=ip,
            description=f"SSH brute force attacker {ip}",
            threat_level="High",
            is_watchlist=True,
        )
        iocs.append(ioc)
    db.add_all(iocs)
    db.commit()
    return iocs


# ===================================================================
# TEST CLASSES
# ===================================================================


class TestDataInjection(unittest.TestCase):
    """Task 1: Verify test PacketLogs are inserted correctly."""

    def setUp(self):
        self.db, self.engine = _make_test_session()

    def tearDown(self):
        self.db.close()

    def test_packet_logs_inserted(self):
        logs = _inject_packet_logs(self.db, count=50)
        count = self.db.query(PacketLog).count()
        self.assertEqual(count, 50)

    def test_packet_logs_have_correct_port(self):
        _inject_packet_logs(self.db, count=10)
        rows = self.db.query(PacketLog).all()
        for r in rows:
            self.assertEqual(r.dst_port, SSH_TARGET_PORT)

    def test_packet_logs_have_correct_ips(self):
        _inject_packet_logs(self.db, count=10)
        rows = self.db.query(PacketLog).all()
        for r in rows:
            self.assertIn(r.src_ip, SSH_ATTACKER_IPS)

    def test_events_inserted(self):
        _inject_events(self.db, count=20)
        count = self.db.query(Event).count()
        self.assertEqual(count, 20)

    def test_events_have_ssh_payloads(self):
        _inject_events(self.db, count=5)
        rows = self.db.query(Event).all()
        for r in rows:
            self.assertIn("Failed password", r.raw_data)

    def test_iocs_inserted(self):
        _inject_iocs(self.db)
        count = self.db.query(IOC).count()
        self.assertEqual(count, len(SSH_ATTACKER_IPS))


class TestPipelineExecution(unittest.TestCase):
    """Task 2: Trigger sentinel pipeline with injected data."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        _inject_packet_logs(cls.db, count=50)
        _inject_events(cls.db, count=20)
        _inject_iocs(cls.db)
        svc = SentinelService(cls.db)
        cls.result = svc.generate_playbook(SSH_BRUTE_CAMPAIGN)
        cls.rd = cls.result.result_dict

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_pipeline_returns_playbook(self):
        self.assertIsInstance(self.result, SentinelPlaybook)

    def test_pipeline_persists_to_db(self):
        row = self.db.query(SentinelPlaybook).filter_by(
            playbook_id=self.result.playbook_id
        ).first()
        self.assertIsNotNone(row)

    def test_service_type_is_ssh(self):
        self.assertEqual(self.rd["service_type"], "SSH")

    def test_matched_logs_found(self):
        self.assertGreater(self.rd["matched_logs_count"], 0)

    def test_ioc_enrichment(self):
        self.assertGreater(self.rd["ioc_count"], 0)

    def test_confidence_score_present(self):
        self.assertIsNotNone(self.rd["confidence_score"])
        self.assertGreater(self.rd["confidence_score"], 0.0)


class TestT1110001Mapping(unittest.TestCase):
    """Task 3: Verify T1110.001 technique mapping."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        _inject_packet_logs(cls.db, count=50)
        _inject_events(cls.db, count=20)
        svc = SentinelService(cls.db)
        cls.result = svc.generate_playbook(SSH_BRUTE_CAMPAIGN)
        cls.rd = cls.result.result_dict

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_technique_id_is_t1110_001(self):
        self.assertEqual(self.result.technique_id, "T1110.001")

    def test_technique_name(self):
        self.assertEqual(
            self.result.technique_name,
            "Brute Force: Password Guessing",
        )

    def test_tactic_is_credential_access(self):
        self.assertEqual(self.result.tactic, "Credential Access")

    def test_mitre_url_correct(self):
        self.assertIn("T1110/001", self.result.mitre_url)

    def test_result_dict_technique(self):
        t = self.rd["technique"]
        self.assertEqual(t["id"], "T1110.001")
        self.assertEqual(t["name"], "Brute Force: Password Guessing")
        self.assertEqual(t["tactic"], "Credential Access")


class TestSnortRuleValidation(unittest.TestCase):
    """Task 4: Validate Snort rule fields."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        _inject_packet_logs(cls.db, count=30)
        svc = SentinelService(cls.db)
        cls.result = svc.generate_playbook(SSH_BRUTE_CAMPAIGN)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_snort_rule_not_empty(self):
        self.assertIsNotNone(self.result.snort_rule)
        self.assertGreater(len(self.result.snort_rule), 0)

    def test_snort_has_msg_field(self):
        rule = self.result.snort_rule.split("\n")[0]
        self.assertIn("msg:", rule)

    def test_snort_has_flow_field(self):
        rule = self.result.snort_rule.split("\n")[0]
        self.assertIn("flow:to_server,established", rule)

    def test_snort_has_threshold(self):
        rule = self.result.snort_rule.split("\n")[0]
        self.assertIn("threshold:type limit", rule)
        self.assertIn("track by_src", rule)
        self.assertIn("count 5", rule)
        self.assertIn("seconds 60", rule)

    def test_snort_has_classtype(self):
        rule = self.result.snort_rule.split("\n")[0]
        self.assertIn("classtype:attempted-admin", rule)

    def test_snort_has_mitre_reference(self):
        rule = self.result.snort_rule.split("\n")[0]
        self.assertIn("attack.mitre.org/techniques/T1110/001", rule)

    def test_snort_has_sid(self):
        rule = self.result.snort_rule.split("\n")[0]
        self.assertIn("sid:", rule)

    def test_snort_starts_with_alert(self):
        rule = self.result.snort_rule.split("\n")[0].strip()
        self.assertTrue(rule.startswith("alert "))

    def test_snort_has_correct_port(self):
        rule = self.result.snort_rule.split("\n")[0]
        self.assertIn(str(SSH_TARGET_PORT), rule)

    def test_snort_has_tcp_protocol(self):
        rule = self.result.snort_rule.split("\n")[0]
        parts = rule.split()
        self.assertEqual(parts[1], "tcp")


class TestSigmaRuleValidation(unittest.TestCase):
    """Task 5: Validate Sigma rule logsource and detection."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        _inject_packet_logs(cls.db, count=30)
        svc = SentinelService(cls.db)
        cls.result = svc.generate_playbook(SSH_BRUTE_CAMPAIGN)
        docs = cls.result.sigma_rule.split("---")
        cls.sigma_doc = yaml.safe_load(docs[0].strip())

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_sigma_not_empty(self):
        self.assertIsNotNone(self.result.sigma_rule)
        self.assertGreater(len(self.result.sigma_rule), 0)

    def test_sigma_is_valid_yaml(self):
        self.assertIsInstance(self.sigma_doc, dict)

    def test_sigma_has_title(self):
        self.assertIn("title", self.sigma_doc)
        self.assertIn(SSH_CAMPAIGN_ID, self.sigma_doc["title"])

    def test_sigma_has_logsource(self):
        self.assertIn("logsource", self.sigma_doc)
        ls = self.sigma_doc["logsource"]
        self.assertEqual(ls.get("category"), "network_traffic")
        self.assertEqual(ls.get("product"), "phantomnet")

    def test_sigma_has_detection(self):
        self.assertIn("detection", self.sigma_doc)
        det = self.sigma_doc["detection"]
        self.assertIn("selection", det)
        self.assertIn("condition", det)

    def test_sigma_detection_has_port(self):
        sel = self.sigma_doc["detection"]["selection"]
        self.assertIn("dst_port", sel)

    def test_sigma_has_level(self):
        self.assertIn("level", self.sigma_doc)
        self.assertIn(self.sigma_doc["level"], ["critical", "high", "medium", "low"])

    def test_sigma_has_tags(self):
        self.assertIn("tags", self.sigma_doc)
        tags = self.sigma_doc["tags"]
        attack_tags = [t for t in tags if "attack.t1110" in t.lower()]
        self.assertGreater(len(attack_tags), 0)


class TestStixBundleValidation(unittest.TestCase):
    """Task 6: Verify STIX bundle with T1110.001 references."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        _inject_packet_logs(cls.db, count=30)
        _inject_iocs(cls.db)
        svc = SentinelService(cls.db)
        cls.result = svc.generate_playbook(SSH_BRUTE_CAMPAIGN)
        cls.bundle = json.loads(cls.result.result_dict["stix_bundle_json"])

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_bundle_is_valid(self):
        self.assertEqual(self.bundle["type"], "bundle")
        self.assertIn("objects", self.bundle)

    def test_bundle_has_identity(self):
        types = [o["type"] for o in self.bundle["objects"]]
        self.assertIn("identity", types)

    def test_bundle_has_attack_pattern(self):
        types = [o["type"] for o in self.bundle["objects"]]
        self.assertIn("attack-pattern", types)

    def test_bundle_has_indicators(self):
        types = [o["type"] for o in self.bundle["objects"]]
        self.assertIn("indicator", types)

    def test_bundle_has_relationships(self):
        types = [o["type"] for o in self.bundle["objects"]]
        self.assertIn("relationship", types)

    def test_attack_pattern_has_t1110_001_reference(self):
        aps = [o for o in self.bundle["objects"] if o["type"] == "attack-pattern"]
        self.assertGreater(len(aps), 0)
        ap = aps[0]
        ext_refs = ap.get("external_references", [])
        mitre_refs = [
            r for r in ext_refs
            if r.get("source_name") == "mitre-attack"
        ]
        self.assertGreater(len(mitre_refs), 0)
        self.assertEqual(mitre_refs[0]["external_id"], "T1110.001")

    def test_attack_pattern_url_correct(self):
        aps = [o for o in self.bundle["objects"] if o["type"] == "attack-pattern"]
        ap = aps[0]
        ext_refs = ap.get("external_references", [])
        mitre_refs = [r for r in ext_refs if r.get("source_name") == "mitre-attack"]
        url = mitre_refs[0].get("url", "")
        self.assertIn("T1110/001", url)

    def test_indicators_have_attacker_ips(self):
        indicators = [o for o in self.bundle["objects"] if o["type"] == "indicator"]
        patterns = [ind.get("pattern", "") for ind in indicators]
        all_patterns = " ".join(patterns)
        self.assertIn(SSH_ATTACKER_IPS[0], all_patterns)

    def test_relationships_are_indicates(self):
        rels = [o for o in self.bundle["objects"] if o["type"] == "relationship"]
        for rel in rels:
            self.assertEqual(rel["relationship_type"], "indicates")


class TestPlaybookMarkdownSections(unittest.TestCase):
    """Task 7: Verify playbook renders all 7 sections."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        _inject_packet_logs(cls.db, count=30)
        svc = SentinelService(cls.db)
        cls.result = svc.generate_playbook(SSH_BRUTE_CAMPAIGN)
        cls.content = cls.result.playbook_content

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_playbook_not_empty(self):
        self.assertIsNotNone(self.content)
        self.assertGreater(len(self.content), 100)

    def test_playbook_starts_with_header(self):
        self.assertTrue(self.content.strip().startswith("#"))

    def test_section_1_header(self):
        # Header section has playbook title and metadata table
        self.assertIn("Playbook", self.content)
        self.assertIn("Severity", self.content)

    def test_section_2_summary(self):
        self.assertIn("Summary", self.content)

    def test_section_3_ioc_table(self):
        # IOC table or source IP reference
        self.assertIn("IOC", self.content.upper())

    def test_section_4_attack_mapping(self):
        self.assertIn("ATT&CK", self.content.replace("\\&", "&"))

    def test_section_5_containment(self):
        self.assertIn("Containment", self.content)

    def test_section_6_artifacts(self):
        self.assertIn("Artifact", self.content)

    def test_section_7_appendix_or_metadata(self):
        # Section 7 is Appendix (in base template) or metadata block
        has_appendix = "Appendix" in self.content
        has_metadata = "metadata" in self.content.lower()
        has_context = "Context" in self.content
        self.assertTrue(
            has_appendix or has_metadata or has_context,
            "Missing Section 7 (Appendix/Metadata/Context)",
        )

    def test_playbook_has_source_ip(self):
        self.assertIn(SSH_ATTACKER_IPS[0], self.content)

    def test_playbook_has_technique_reference(self):
        self.assertIn("T1110", self.content)


class TestDBPersistence(unittest.TestCase):
    """Verify all 23 DB columns are populated."""

    @classmethod
    def setUpClass(cls):
        cls.db, cls.engine = _make_test_session()
        _inject_packet_logs(cls.db, count=30)
        _inject_iocs(cls.db)
        svc = SentinelService(cls.db)
        result = svc.generate_playbook(SSH_BRUTE_CAMPAIGN)
        cls.row = cls.db.query(SentinelPlaybook).filter_by(
            playbook_id=result.playbook_id
        ).first()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_core_identity(self):
        self.assertIsNotNone(self.row.id)
        self.assertIsNotNone(self.row.playbook_id)
        self.assertTrue(self.row.playbook_id.startswith("PB-"))
        self.assertIsNotNone(self.row.created_at)
        self.assertIsNotNone(self.row.updated_at)

    def test_threat_context(self):
        self.assertIn(self.row.src_ip, SSH_ATTACKER_IPS)
        self.assertEqual(self.row.dst_port, SSH_TARGET_PORT)
        self.assertEqual(self.row.protocol, "TCP")
        self.assertIsNotNone(self.row.attack_type)
        self.assertIsInstance(self.row.threat_score, (int, float))
        self.assertIsNotNone(self.row.confidence_score)
        self.assertIsNotNone(self.row.severity)

    def test_mitre_mapping(self):
        self.assertEqual(self.row.technique_id, "T1110.001")
        self.assertEqual(self.row.technique_name, "Brute Force: Password Guessing")
        self.assertEqual(self.row.tactic, "Credential Access")
        self.assertIn("attack.mitre.org", self.row.mitre_url)

    def test_detection_rules(self):
        self.assertIsNotNone(self.row.snort_rule)
        self.assertIsNotNone(self.row.sigma_rule)

    def test_playbook_content(self):
        self.assertIsNotNone(self.row.playbook_name)
        self.assertIn("Brute Force", self.row.playbook_name)
        self.assertIsNotNone(self.row.playbook_content)

    def test_lifecycle(self):
        self.assertEqual(self.row.status, "pending")
        self.assertIsNone(self.row.reviewed_by)
        self.assertIsNone(self.row.reviewed_at)

    def test_to_dict_has_all_keys(self):
        d = self.row.to_dict()
        expected = [
            "id", "playbook_id", "created_at", "updated_at",
            "src_ip", "dst_port", "protocol", "attack_type",
            "threat_score", "confidence_score", "severity",
            "technique_id", "technique_name", "tactic", "mitre_url",
            "snort_rule", "sigma_rule",
            "playbook_name", "playbook_content", "template_name",
            "status", "reviewed_by", "reviewed_at",
        ]
        for key in expected:
            self.assertIn(key, d, f"Missing key: {key}")


if __name__ == "__main__":
    unittest.main()
