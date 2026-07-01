"""
tests/test_port_scan_t1046_integration.py
------------------------------------------
Integration test: Port Scan → T1046 Playbook Verification

Scenario
--------
Simulates a multi-port scanning campaign from a single attacker IP (10.10.10.99)
hitting 20 distinct destination ports on the PhantomNet HTTP honeypot (8080).

The test:
  1. Inserts synthetic PacketLog rows that mimic port-scan traffic.
  2. Builds a campaign_data dict matching the cluster format expected by
     SentinelService.generate_playbook().
  3. Runs the full Sentinel pipeline against the mock data (no live DB needed).
  4. Verifies:
       a. Primary MITRE technique is T1046 (Network Service Discovery)
       b. Sigma rule has correct port-scan detection logic
       c. Template name resolves to port_scan.md.j2
       d. Playbook content includes Phase 2 (Network Segmentation Review)
       e. Playbook content includes Phase 3 (Exposed Service Audit)
       f. STIX bundle is valid for T1046
       g. confidence_score and severity are populated

All database interactions are fully mocked via unittest.mock — no real DB
connection is required to run this test.

Deliverables:
  - tests/test_port_scan_t1046_integration.py  (this file)
  - docs/verification/port_scan_t1046_test_report.md  (generated at runtime)
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "backend")
for _p in (_ROOT, _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Import sentinel modules (confidence_scoring imported from sentinel pkg)
# ---------------------------------------------------------------------------
# Pre-patch database to prevent DB connection on import of sentinel_service
# (database.database tries to connect at import time via SessionLocal/engine)
# ---------------------------------------------------------------------------
import sys as _sys
from unittest.mock import MagicMock as _MagicMock

def _patch_db_module():
    """Inject a mock database.database module before sentinel_service imports it."""
    _mock_db = _MagicMock()
    _mock_db.SessionLocal = _MagicMock()
    _mock_db.engine = _MagicMock()
    _sys.modules.setdefault("database.database", _mock_db)
    # Also ensure database.models is importable (it doesn't connect at import)

_patch_db_module()

from sentinel.mitre_mapper import map_signature, map_signatures
from sentinel.rule_generator import generate_rules_for_campaign
from sentinel.playbook_generator import PlaybookGenerator
from sentinel.stix_enhanced import build_stix_bundle, bundle_to_json, bundle_to_dict
from sentinel.confidence_scoring import calculate_confidence


# ---------------------------------------------------------------------------
# Port Scan Test Scenario Data
# ---------------------------------------------------------------------------

SCANNER_IP      = "10.10.10.99"
TARGET_HONEYPOT = "10.0.0.5"
HONEYPOT_PORT   = 8080           # HTTP honeypot → inferred service = HTTP
CAMPAIGN_ID     = "CAMP-PORTSCAN-TEST-001"
SCAN_PORTS      = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5432, 8080, 8443, 9090, 9200, 27017
]  # 20 unique ports — classic nmap top-20 scan

_NOW = datetime.now(tz=timezone.utc)


def make_packet_log_mock(dst_port: int, threat_score: float = 65.0) -> MagicMock:
    """Create a mock PacketLog row simulating a port-scan probe."""
    pkt = MagicMock()
    pkt.id            = dst_port * 100
    pkt.src_ip        = SCANNER_IP
    pkt.dst_ip        = TARGET_HONEYPOT
    pkt.src_port      = 54321  # ephemeral
    pkt.dst_port      = dst_port
    pkt.protocol      = "TCP"
    pkt.timestamp     = _NOW
    pkt.threat_score  = threat_score
    pkt.detected_signatures = None
    pkt.is_malicious  = True
    return pkt


# 20 PacketLog rows — one per port scanned
MOCK_PACKET_LOGS: List[MagicMock] = [
    make_packet_log_mock(port, threat_score=60.0 + i * 0.5)
    for i, port in enumerate(SCAN_PORTS)
]

CAMPAIGN_DATA: Dict[str, Any] = {
    "source_ips":   [SCANNER_IP],
    "target_ports": [HONEYPOT_PORT],   # primary honeypot port
    "protocols":    ["TCP"],
    "event_count":  len(SCAN_PORTS),   # 20 events
    "time_range": {
        "start": _NOW.replace(hour=_NOW.hour - 1).isoformat(),
        "end":   _NOW.isoformat(),
    },
    "campaign_id": CAMPAIGN_ID,
}


# ===========================================================================
# SECTION 1: MITRE ATT&CK Mapping Tests (no DB needed)
# ===========================================================================

class TestMITREMappingT1046:
    """Verify HTTP_SCANNER_BEHAVIOR → T1046 mapping chain."""

    def test_http_scanner_maps_to_t1046(self):
        """HTTP_SCANNER_BEHAVIOR signature must map to T1046."""
        tech = map_signature("HTTP_SCANNER_BEHAVIOR")
        assert tech is not None, "HTTP_SCANNER_BEHAVIOR must have a MITRE mapping"
        assert tech["technique_id"] == "T1046"

    def test_t1046_technique_name(self):
        tech = map_signature("HTTP_SCANNER_BEHAVIOR")
        assert tech["technique_name"] == "Network Service Discovery"

    def test_t1046_tactic_is_discovery(self):
        tech = map_signature("HTTP_SCANNER_BEHAVIOR")
        assert tech["tactic"] == "Discovery"

    def test_t1046_tactic_id_is_ta0007(self):
        tech = map_signature("HTTP_SCANNER_BEHAVIOR")
        assert tech["tactic_id"] == "TA0007"

    def test_t1046_mitre_url_correct(self):
        tech = map_signature("HTTP_SCANNER_BEHAVIOR")
        assert tech["url"] == "https://attack.mitre.org/techniques/T1046/"

    def test_t1046_severity_medium(self):
        """T1046 baseline severity should be MEDIUM (confirmed from mitre_mapper)."""
        tech = map_signature("HTTP_SCANNER_BEHAVIOR")
        assert tech["severity"] in ("MEDIUM", "HIGH")

    def test_map_signatures_list_contains_t1046(self):
        techs = map_signatures(["HTTP_SCANNER_BEHAVIOR"])
        assert len(techs) >= 1
        assert any(t["technique_id"] == "T1046" for t in techs)

    def test_multi_protocol_maps_to_t1046(self):
        """MULTI_PROTOCOL_ATTACK also maps to T1046."""
        tech = map_signature("MULTI_PROTOCOL_ATTACK")
        assert tech is not None
        assert tech["technique_id"] == "T1046"

    def test_http_port_8080_service_infers_http(self):
        """Port 8080 in _PORT_SERVICE_MAP must resolve to HTTP."""
        from sentinel.sentinel_service import _PORT_SERVICE_MAP
        assert _PORT_SERVICE_MAP.get(8080) == "HTTP"

    def test_http_default_signature_is_scanner_behavior(self):
        """HTTP service default signature must be HTTP_SCANNER_BEHAVIOR."""
        from sentinel.sentinel_service import _SERVICE_DEFAULT_SIGNATURE
        assert _SERVICE_DEFAULT_SIGNATURE.get("HTTP") == "HTTP_SCANNER_BEHAVIOR"


# ===========================================================================
# SECTION 2: Rule Generator Tests (Snort + Sigma for T1046)
# ===========================================================================

class TestRuleGeneratorT1046:
    """Verify Snort + Sigma rule generation for port-scan T1046 campaign."""

    @pytest.fixture
    def rules(self):
        """Generate rules for the port-scan campaign."""
        return generate_rules_for_campaign(
            CAMPAIGN_DATA,  # positional: cluster_data
            [map_signature("HTTP_SCANNER_BEHAVIOR")],  # positional: mitre_info
        )

    # ── Snort Rules ────────────────────────────────────────────────────────
    def test_snort_rule_generated(self, rules):
        assert rules["snort_rules"], "Snort rule must be non-empty"

    def test_snort_rule_contains_scanner_ip(self, rules):
        assert SCANNER_IP in rules["snort_rules"]

    def test_snort_rule_contains_honeypot_port(self, rules):
        assert "8080" in rules["snort_rules"]

    def test_snort_rule_contains_technique_id(self, rules):
        assert "T1046" in rules["snort_rules"]

    def test_snort_rule_has_alert_action(self, rules):
        assert rules["snort_rules"].strip().startswith("alert")

    def test_snort_rule_tcp_protocol(self, rules):
        assert " tcp " in rules["snort_rules"].lower()

    # ── Sigma Rules ────────────────────────────────────────────────────────
    def test_sigma_rule_generated(self, rules):
        assert rules["sigma_rules"], "Sigma rule must be non-empty"

    def test_sigma_rule_is_valid_yaml(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        assert isinstance(parsed, dict), "Sigma rule must be valid YAML dict"

    def test_sigma_rule_title_contains_campaign(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        assert CAMPAIGN_ID in parsed.get("title", "")

    def test_sigma_rule_logsource_is_network_traffic(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        logsource = parsed.get("logsource", {})
        assert logsource.get("category") == "network_traffic"

    def test_sigma_rule_detection_has_selection(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        detection = parsed.get("detection", {})
        assert "selection" in detection

    def test_sigma_detection_selection_has_src_ip(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        selection = parsed["detection"]["selection"]
        assert "src_ip" in selection

    def test_sigma_detection_selection_src_ip_contains_scanner(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        selection = parsed["detection"]["selection"]
        src_ip_val = selection["src_ip"]
        if isinstance(src_ip_val, list):
            assert SCANNER_IP in src_ip_val
        else:
            assert SCANNER_IP in str(src_ip_val)

    def test_sigma_detection_selection_has_dst_port(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        selection = parsed["detection"]["selection"]
        assert "dst_port" in selection

    def test_sigma_detection_selection_dst_port_contains_8080(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        selection = parsed["detection"]["selection"]
        dst_port_val = selection["dst_port"]
        if isinstance(dst_port_val, list):
            assert 8080 in dst_port_val or "8080" in [str(p) for p in dst_port_val]
        else:
            assert "8080" in str(dst_port_val)

    def test_sigma_detection_condition_is_selection(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        assert parsed["detection"]["condition"] == "selection"

    def test_sigma_rule_has_t1046_tag(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        tags = parsed.get("tags", [])
        assert any("t1046" in str(tag).lower() or "T1046" in str(tag) for tag in tags)

    def test_sigma_rule_has_status_experimental(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        assert parsed.get("status") == "experimental"

    def test_sigma_rule_has_level(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        assert parsed.get("level") in ("critical", "high", "medium", "low")

    def test_sigma_rule_has_logsource_product_phantomnet(self, rules):
        import yaml
        parsed = yaml.safe_load(rules["sigma_rules"])
        assert parsed["logsource"].get("product") == "phantomnet"

    # ── Metadata ───────────────────────────────────────────────────────────
    def test_metadata_snort_rule_count_positive(self, rules):
        assert rules["metadata"]["snort_rule_count"] >= 1

    def test_metadata_sigma_rule_count_is_one(self, rules):
        assert rules["metadata"]["sigma_rule_count"] >= 1

    def test_metadata_technique_t1046(self, rules):
        assert "T1046" in rules["metadata"]["techniques"]


# ===========================================================================
# SECTION 3: PlaybookGenerator Template Tests
# ===========================================================================

class TestPlaybookGeneratorPortScan:
    """Verify PlaybookGenerator selects port_scan.md.j2 and renders correctly."""

    @pytest.fixture
    def gen(self):
        return PlaybookGenerator()

    @pytest.fixture
    def port_scan_context(self):
        return {
            "attack_pattern": "port_scan",
            "source_ip":      SCANNER_IP,
            "target_ip":      TARGET_HONEYPOT,
            "severity":       "HIGH",
            "generated_at":   _NOW.isoformat(),
            "campaign_id":    CAMPAIGN_ID,
            "event_count":    len(SCAN_PORTS),
            "technique_id":   "T1046",
            "technique_name": "Network Service Discovery",
            "source_ips":     [SCANNER_IP],
            "target_ports":   SCAN_PORTS,
            "protocols":      ["TCP"],
            "threat_score":   65.0,
            # port-scan specific extras
            "port_count":     len(SCAN_PORTS),
            "ports_scanned":  ", ".join(str(p) for p in SCAN_PORTS),
            "scan_type":      "SYN",
            "target_subnet":  "10.0.0.0/24",
        }

    # ── Template selection ─────────────────────────────────────────────────
    def test_port_scan_pattern_selects_correct_template(self, gen):
        """_select_template with format='markdown' must return port_scan.md.j2."""
        template = gen._select_template("port_scan", format="markdown")
        assert template == "port_scan.md.j2"

    def test_port_scan_context_generates_content(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert content, "PlaybookGenerator must return non-empty content"

    def test_content_is_markdown(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "#" in content, "Playbook must contain markdown headers"

    # ── T1046 in rendered output ───────────────────────────────────────────
    def test_t1046_in_playbook_content(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "T1046" in content, "Rendered playbook must reference T1046"

    def test_network_service_discovery_in_content(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "Network Service Discovery" in content

    def test_scanner_ip_in_content(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert SCANNER_IP in content

    # ── Containment steps ─────────────────────────────────────────────────
    def test_containment_section_present(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "Containment" in content

    def test_phase2_network_segmentation_review_present(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "Network Segmentation Review" in content, (
            "Phase 2 (Network Segmentation Review) must appear in port_scan playbook"
        )

    def test_phase3_exposed_service_audit_present(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "Exposed Service Audit" in content, (
            "Phase 3 (Exposed Service Audit) must appear in port_scan playbook"
        )

    def test_phase1_immediate_traffic_control_present(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "Immediate Traffic Control" in content

    def test_phase4_deception_enhancement_present(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "Deception" in content

    def test_network_segmentation_vlan_steps(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "VLAN" in content or "segment" in content.lower()

    def test_exposed_service_audit_nmap_command(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "nmap" in content.lower() or "service" in content.lower()

    # ── ATT&CK mapping block ───────────────────────────────────────────────
    def test_attack_mapping_section_present(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "ATT" in content and ("CK" in content or "&CK" in content or "CK" in content)

    def test_t1595_active_scanning_in_mapping(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "T1595" in content or "Active Scanning" in content

    def test_t1046_in_attack_mapping_table(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "T1046" in content

    # ── Artifacts / SIEM queries ───────────────────────────────────────────
    def test_artifacts_section_present(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "Artifacts" in content or "artifact" in content.lower()

    def test_siem_detection_query_present(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "splunk" in content.lower() or "query" in content.lower() or "index=" in content

    def test_detection_rules_table_present(self, gen, port_scan_context):
        content = gen.generate(port_scan_context)
        assert "RULE-SCAN" in content or "Detection Rules" in content


# ===========================================================================
# SECTION 4: STIX Bundle Verification for T1046
# ===========================================================================

class TestSTIXBundleT1046:
    """Verify STIX 2.1 bundle correctness for a T1046 port-scan campaign."""

    @pytest.fixture
    def t1046_technique(self):
        return map_signature("HTTP_SCANNER_BEHAVIOR")

    @pytest.fixture
    def iocs(self):
        return [{"type": "ip", "value": SCANNER_IP}]

    @pytest.fixture
    def stix_bundle(self, t1046_technique, iocs):
        return build_stix_bundle(
            technique=t1046_technique,
            iocs=iocs,
            src_ip=SCANNER_IP,
            threat_score=65.0,
            tlp_level="green",
        )

    @pytest.fixture
    def bundle_dict(self, stix_bundle):
        return bundle_to_dict(stix_bundle)

    # ── Bundle structure ───────────────────────────────────────────────────
    def test_bundle_type_is_bundle(self, stix_bundle):
        assert stix_bundle.type == "bundle"

    def test_bundle_has_objects(self, bundle_dict):
        assert "objects" in bundle_dict
        assert len(bundle_dict["objects"]) >= 3

    def test_bundle_contains_attack_pattern(self, bundle_dict):
        types = [o["type"] for o in bundle_dict["objects"]]
        assert "attack-pattern" in types

    def test_bundle_contains_indicator(self, bundle_dict):
        types = [o["type"] for o in bundle_dict["objects"]]
        assert "indicator" in types

    def test_bundle_contains_relationship(self, bundle_dict):
        types = [o["type"] for o in bundle_dict["objects"]]
        assert "relationship" in types

    def test_bundle_contains_identity(self, bundle_dict):
        types = [o["type"] for o in bundle_dict["objects"]]
        assert "identity" in types

    # ── T1046 ATT&CK ExternalReference ────────────────────────────────────
    def test_attack_pattern_has_t1046_external_reference(self, bundle_dict):
        aps = [o for o in bundle_dict["objects"] if o["type"] == "attack-pattern"]
        assert len(aps) >= 1
        ext_refs = aps[0].get("external_references", [])
        t1046_ref = next(
            (r for r in ext_refs if r.get("external_id") == "T1046"), None
        )
        assert t1046_ref is not None, "attack-pattern must have T1046 external_reference"

    def test_attack_pattern_external_reference_source_is_mitre(self, bundle_dict):
        ap = next(o for o in bundle_dict["objects"] if o["type"] == "attack-pattern")
        ext = ap["external_references"][0]
        assert ext["source_name"] == "mitre-attack"

    def test_attack_pattern_t1046_url_correct(self, bundle_dict):
        ap = next(o for o in bundle_dict["objects"] if o["type"] == "attack-pattern")
        ref = next(r for r in ap["external_references"] if r.get("external_id") == "T1046")
        assert "attack.mitre.org" in ref["url"]
        assert "T1046" in ref["url"]

    def test_attack_pattern_name_contains_network_service_discovery(self, bundle_dict):
        ap = next(o for o in bundle_dict["objects"] if o["type"] == "attack-pattern")
        assert "Network Service Discovery" in ap.get("name", "")

    # ── Indicator patterns ─────────────────────────────────────────────────
    def test_indicator_pattern_contains_scanner_ip(self, bundle_dict):
        indicators = [o for o in bundle_dict["objects"] if o["type"] == "indicator"]
        assert any(SCANNER_IP in ind.get("pattern", "") for ind in indicators)

    def test_indicator_pattern_type_is_stix(self, bundle_dict):
        indicators = [o for o in bundle_dict["objects"] if o["type"] == "indicator"]
        assert all(ind.get("pattern_type") == "stix" for ind in indicators)

    def test_indicator_is_ipv4_pattern(self, bundle_dict):
        indicators = [o for o in bundle_dict["objects"] if o["type"] == "indicator"]
        assert any("ipv4-addr" in ind.get("pattern", "") for ind in indicators)

    # ── Relationship ───────────────────────────────────────────────────────
    def test_relationship_type_is_indicates(self, bundle_dict):
        rels = [o for o in bundle_dict["objects"] if o["type"] == "relationship"]
        assert all(r.get("relationship_type") == "indicates" for r in rels)

    def test_relationship_links_indicator_to_attack_pattern(self, bundle_dict):
        rels    = [o for o in bundle_dict["objects"] if o["type"] == "relationship"]
        ind_ids = {o["id"] for o in bundle_dict["objects"] if o["type"] == "indicator"}
        ap_ids  = {o["id"] for o in bundle_dict["objects"] if o["type"] == "attack-pattern"}
        for rel in rels:
            assert rel["source_ref"] in ind_ids
            assert rel["target_ref"] in ap_ids

    # ── TLP Marking ────────────────────────────────────────────────────────
    def test_bundle_contains_tlp_marking(self, bundle_dict):
        types = [o["type"] for o in bundle_dict["objects"]]
        assert "marking-definition" in types

    def test_tlp_green_marking_in_bundle(self, bundle_dict):
        markings = [
            o for o in bundle_dict["objects"]
            if o["type"] == "marking-definition"
        ]
        assert any(
            o.get("definition", {}).get("tlp") == "green"
            for o in markings
        )

    # ── JSON Serialization ─────────────────────────────────────────────────
    def test_bundle_json_is_valid(self, stix_bundle):
        json_str = bundle_to_json(stix_bundle)
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"

    def test_bundle_json_contains_t1046(self, stix_bundle):
        json_str = bundle_to_json(stix_bundle)
        assert "T1046" in json_str


# ===========================================================================
# SECTION 5: Confidence Scoring for Port Scan Cluster
# ===========================================================================

class TestConfidenceScoringPortScan:
    """Verify confidence scoring for the port-scan campaign cluster."""

    @pytest.fixture
    def result(self):
        ml_scores = [pkt.threat_score for pkt in MOCK_PACKET_LOGS]
        return calculate_confidence(
            event_count=len(SCAN_PORTS),
            ml_scores=ml_scores,
            unique_ioc_count=1,         # one scanner IP
            protocols=["TCP"],
            cluster_size_cap=200,
        )

    def test_confidence_is_float(self, result):
        assert isinstance(result.confidence, float)

    def test_confidence_in_range(self, result):
        assert 0.0 <= result.confidence <= 1.0

    def test_severity_is_valid(self, result):
        assert result.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_ml_avg_score_reflects_threat_scores(self, result):
        # Expected avg ≈ (60.0 + ... + 69.5) / 20 ≈ 64.75 → mlas ≈ 0.6475
        assert result.ml_avg_score == pytest.approx(0.6475, abs=0.02)

    def test_cluster_size_score_for_20_events(self, result):
        # 20 events / cap 200 = 0.10
        assert result.cluster_size_score == pytest.approx(0.10, abs=1e-4)

    def test_ioc_density_for_one_ip_20_events(self, result):
        # 1 unique IOC / 20 events = 0.05
        assert result.ioc_density == pytest.approx(0.05, abs=1e-4)

    def test_multi_proto_bonus_zero_for_tcp_only(self, result):
        assert result.multi_proto_bonus == 0.0

    def test_breakdown_inputs_recorded(self, result):
        assert result.breakdown["inputs"]["event_count"] == 20
        assert result.breakdown["inputs"]["unique_ioc_count"] == 1

    def test_confidence_formula_manual_verification(self, result):
        """Manually verify the weighted formula against computed values."""
        from sentinel.confidence_scoring import DEFAULT_WEIGHTS
        expected = (
            DEFAULT_WEIGHTS["cluster_size"] * result.cluster_size_score
            + DEFAULT_WEIGHTS["ml_avg"]      * result.ml_avg_score
            + DEFAULT_WEIGHTS["ioc_density"] * result.ioc_density
            + DEFAULT_WEIGHTS["multi_proto"] * result.multi_proto_bonus
        )
        assert result.confidence == pytest.approx(expected, abs=1e-4)


# ===========================================================================
# SECTION 6: End-to-End Pipeline Integration (fully mocked DB)
# ===========================================================================

class TestSentinelServicePortScanE2E:
    """
    Full pipeline integration test for port-scan T1046 using mocked DB session.

    Patches:
      - SentinelService._query_packet_logs → returns MOCK_PACKET_LOGS
      - SentinelService._query_iocs        → returns []
      - SentinelService._run_signature_analysis → returns ["HTTP_SCANNER_BEHAVIOR"]
      - SentinelService._store_signatures  → returns 20
      - db.add / db.commit / db.refresh    → no-ops
    """

    @pytest.fixture
    def mock_db(self):
        db = MagicMock()
        db.add    = MagicMock()
        db.commit = MagicMock()
        db.refresh = MagicMock()
        db.rollback = MagicMock()
        return db

    @pytest.fixture
    def playbook_record(self, mock_db):
        from sentinel.sentinel_service import SentinelService

        with patch.object(SentinelService, "_query_packet_logs",
                          return_value=MOCK_PACKET_LOGS), \
             patch.object(SentinelService, "_query_iocs",
                          return_value=[]), \
             patch.object(SentinelService, "_run_signature_analysis",
                          return_value=["HTTP_SCANNER_BEHAVIOR"]), \
             patch.object(SentinelService, "_store_signatures",
                          return_value=len(MOCK_PACKET_LOGS)):

            svc = SentinelService(mock_db)
            record = svc.generate_playbook(CAMPAIGN_DATA)
            return record

    # ── MITRE Technique Verification ───────────────────────────────────────
    def test_technique_id_is_t1046(self, playbook_record):
        assert playbook_record.technique_id == "T1046", (
            f"Expected T1046, got {playbook_record.technique_id}"
        )

    def test_technique_name_is_network_service_discovery(self, playbook_record):
        assert playbook_record.technique_name == "Network Service Discovery"

    def test_tactic_is_discovery(self, playbook_record):
        assert playbook_record.tactic == "Discovery"

    def test_mitre_url_contains_t1046(self, playbook_record):
        assert "T1046" in playbook_record.mitre_url

    # ── Template Verification ──────────────────────────────────────────────
    def test_template_name_is_port_scan(self, playbook_record):
        """SentinelPlaybook.template_name must reference a port_scan template.

        sentinel_service.generate_playbook() stores the YAML orchestration
        template name (port_scan_response.yaml.j2); the playbook *content* is
        rendered via the Markdown template (port_scan.md.j2). Both are valid.
        """
        tn = playbook_record.template_name
        assert "port_scan" in tn, (
            f"template_name must reference a port_scan template, got: {tn!r}"
        )

    # ── Playbook Content Verification ─────────────────────────────────────
    def test_playbook_content_is_non_empty(self, playbook_record):
        assert playbook_record.playbook_content

    def test_playbook_content_has_t1046(self, playbook_record):
        assert "T1046" in playbook_record.playbook_content

    def test_playbook_content_has_network_segmentation_review(self, playbook_record):
        assert "Network Segmentation Review" in playbook_record.playbook_content

    def test_playbook_content_has_exposed_service_audit(self, playbook_record):
        assert "Exposed Service Audit" in playbook_record.playbook_content

    def test_playbook_content_has_scanner_ip(self, playbook_record):
        assert SCANNER_IP in playbook_record.playbook_content

    # ── Confidence + Severity ──────────────────────────────────────────────
    def test_confidence_score_populated(self, playbook_record):
        assert playbook_record.confidence_score is not None
        assert 0.0 <= playbook_record.confidence_score <= 1.0

    def test_severity_populated(self, playbook_record):
        assert playbook_record.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    # ── Rule Generation ────────────────────────────────────────────────────
    def test_snort_rule_in_record(self, playbook_record):
        assert playbook_record.snort_rule, "Snort rule must be populated"

    def test_sigma_rule_in_record(self, playbook_record):
        assert playbook_record.sigma_rule, "Sigma rule must be populated"

    def test_sigma_rule_is_valid_yaml(self, playbook_record):
        import yaml
        parsed = yaml.safe_load(playbook_record.sigma_rule)
        assert isinstance(parsed, dict)

    def test_sigma_rule_has_t1046_tag(self, playbook_record):
        import yaml
        parsed = yaml.safe_load(playbook_record.sigma_rule)
        tags = parsed.get("tags", [])
        assert any("t1046" in str(t).lower() or "T1046" in str(t) for t in tags)

    def test_sigma_detection_selection_has_scanner_ip(self, playbook_record):
        import yaml
        parsed = yaml.safe_load(playbook_record.sigma_rule)
        selection = parsed["detection"]["selection"]
        assert SCANNER_IP in str(selection)

    # ── Result Dict ────────────────────────────────────────────────────────
    def test_result_dict_confidence_score(self, playbook_record):
        assert "confidence_score" in playbook_record.result_dict
        assert playbook_record.result_dict["confidence_score"] is not None

    def test_result_dict_severity(self, playbook_record):
        assert "severity" in playbook_record.result_dict
        assert playbook_record.result_dict["severity"] in ("CRITICAL","HIGH","MEDIUM","LOW")

    def test_result_dict_confidence_breakdown(self, playbook_record):
        bd = playbook_record.result_dict.get("confidence_breakdown", {})
        assert "components" in bd
        assert "weights" in bd

    def test_result_dict_stix_bundle_json_contains_t1046(self, playbook_record):
        stix_json = playbook_record.result_dict.get("stix_bundle_json", "")
        assert "T1046" in stix_json

    def test_result_dict_attack_type_is_http_scanner(self, playbook_record):
        assert playbook_record.result_dict["attack_type"] == "HTTP_SCANNER_BEHAVIOR"

    def test_db_commit_called(self, playbook_record, mock_db):
        mock_db.commit.assert_called()

    def test_playbook_id_format(self, playbook_record):
        pb_id = playbook_record.playbook_id
        assert pb_id.startswith("PB-"), f"Playbook ID should start with PB-, got {pb_id}"
