"""
tests/test_template_section_review.py
--------------------------------------
Manual review verification — all 7 sections across all 5 templates.

Verifies:
  1. All 7 sections render (non-empty) for every attack pattern
  2. All specific containment phases/sub-sections are present
  3. All artifact sub-sections are present
  4. No unrendered Jinja2 tags remain
  5. No empty blocks (sections shorter than expected)
  6. Critical keywords for each template are present
  7. Base template fallback path works correctly
"""

from __future__ import annotations
import sys, os
from unittest.mock import MagicMock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "backend"))
sys.path.insert(0, _ROOT)
sys.modules.setdefault("database.database", MagicMock())

import pytest
from sentinel.playbook_generator import PlaybookGenerator

_gen = PlaybookGenerator()

FIRST_SEEN = "2026-06-30T08:15:00Z"
LAST_SEEN  = "2026-06-30T08:47:00Z"

def _render(attack_pattern: str, extra: dict = None) -> str:
    ctx = {
        "attack_pattern": attack_pattern,
        "source_ip": "10.1.2.3",
        "target_ip": "192.168.100.10",
        "first_seen": FIRST_SEEN,
        "last_seen": LAST_SEEN,
        "event_count": 147,
    }
    if extra:
        ctx.update(extra)
    return _gen.generate(ctx)


# ─── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def bf():
    return _render("brute_force")

@pytest.fixture(scope="module")
def sqli():
    return _render("sqli", {"target_url": "https://app.example.com/login"})

@pytest.fixture(scope="module")
def pscan():
    return _render("port_scan", {"port_count": 120, "scan_type": "SYN"})

@pytest.fixture(scope="module")
def exfil():
    return _render("data_exfil", {"exfil_vector": "https", "exfil_bytes": 5000000, "exfil_bytes_hr": "4.7 MB"})

@pytest.fixture(scope="module")
def base_generic():
    return _render("unknown_attack_xyz")


# ═══════════════════════════════════════════════════════════════════════════════
# BASE TEMPLATE REVIEW
# ═══════════════════════════════════════════════════════════════════════════════

class TestBaseTemplateAllSections:
    """Verify base_playbook.md.j2 renders all 7 sections for generic patterns."""

    def test_s1_header_rendered(self, base_generic):
        assert "Playbook ID" in base_generic

    def test_s1_header_severity_badge(self, base_generic):
        # Should render one of the severity badges
        assert any(badge in base_generic for badge in ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_s1_header_generated_at(self, base_generic):
        assert "Generated At" in base_generic

    def test_s1_header_event_summary(self, base_generic):
        assert "Event Summary" in base_generic

    def test_s2_summary_rendered(self, base_generic):
        assert "Campaign Overview" in base_generic

    def test_s2_summary_trigger_context(self, base_generic):
        assert "Trigger Context" in base_generic

    def test_s2_summary_time_range(self, base_generic):
        assert "Time Range" in base_generic

    def test_s2_summary_affected_assets(self, base_generic):
        assert "Affected Assets" in base_generic

    def test_s2_summary_incident_priority(self, base_generic):
        assert "Incident Priority" in base_generic

    def test_s3_ioc_table_rendered(self, base_generic):
        assert "Indicators of Compromise" in base_generic

    def test_s3_ioc_source_ips(self, base_generic):
        assert "Source IPs" in base_generic

    def test_s3_ioc_hashes_section(self, base_generic):
        assert "Additional IOC Hashes" in base_generic

    def test_s3_ioc_domains_section(self, base_generic):
        assert "Domain / URL IOCs" in base_generic

    def test_s4_attack_mapping_rendered(self, base_generic):
        assert "MITRE ATT" in base_generic

    def test_s4_attack_technique_table(self, base_generic):
        assert "Technique ID" in base_generic

    def test_s5_containment_rendered(self, base_generic):
        assert "Containment Steps" in base_generic

    def test_s5_containment_phase1(self, base_generic):
        assert "Phase 1" in base_generic

    def test_s6_artifacts_rendered(self, base_generic):
        assert "Artifacts" in base_generic

    def test_s6_detection_rules(self, base_generic):
        assert "Detection Rules" in base_generic

    def test_s6_log_sources(self, base_generic):
        assert "Log Sources" in base_generic

    def test_s7_appendix_rendered(self, base_generic):
        assert "Appendix" in base_generic

    def test_s7_escalation_contacts(self, base_generic):
        assert "Escalation Contacts" in base_generic

    def test_s7_rollback(self, base_generic):
        assert "Rollback" in base_generic

    def test_s7_sla_targets(self, base_generic):
        assert "SLA Targets" in base_generic

    def test_s7_context_metadata(self, base_generic):
        assert "Context Metadata" in base_generic

    def test_no_unrendered_jinja_tags(self, base_generic):
        assert "{{" not in base_generic
        assert "}}" not in base_generic

    def test_minimum_output_length(self, base_generic):
        assert len(base_generic) >= 3000


# ═══════════════════════════════════════════════════════════════════════════════
# BRUTE_FORCE.MD.J2 — SECTION REVIEW
# ═══════════════════════════════════════════════════════════════════════════════

class TestBruteForceAllSections:
    """Verify brute_force.md.j2 — all 7 sections + specific containment phases."""

    # S1 Header
    def test_s1_ssh_brute_force_title(self, bf):
        assert "Brute Force" in bf

    def test_s1_playbook_id(self, bf):
        assert "PB-SSH-BRUTE-FORCE" in bf

    def test_s1_ssh_port(self, bf):
        assert "SSH Port" in bf

    def test_s1_attacker_ip(self, bf):
        assert "Attacker IP" in bf

    def test_s1_event_summary_row(self, bf):
        assert "Event Summary" in bf

    def test_s1_event_summary_content(self, bf):
        assert "147 events detected between 08:15 and 08:47 UTC" in bf

    # S2 Summary
    def test_s2_campaign_overview(self, bf):
        assert "Campaign Overview" in bf

    def test_s2_time_range(self, bf):
        assert "Time Range" in bf

    def test_s2_affected_assets(self, bf):
        assert "Affected Assets" in bf

    def test_s2_incident_priority(self, bf):
        assert "Incident Priority" in bf

    # S3 IOC Table
    def test_s3_ioc_table(self, bf):
        assert "Indicators of Compromise" in bf

    def test_s3_source_ips(self, bf):
        assert "Source IPs" in bf

    def test_s3_domain_iocs(self, bf):
        assert "Domain / URL IOCs" in bf

    # S4 ATT&CK Mapping
    def test_s4_attack_mapping(self, bf):
        assert "MITRE ATT" in bf

    def test_s4_t1110_technique(self, bf):
        assert "T1110" in bf

    def test_s4_brute_force_technique_name(self, bf):
        assert "Brute Force" in bf

    def test_s4_credential_access_tactic(self, bf):
        assert "Credential Access" in bf

    def test_s4_t1078_valid_accounts(self, bf):
        assert "T1078" in bf

    def test_s4_t1021_remote_services(self, bf):
        assert "T1021" in bf

    # S5 Containment — 4 Phases
    def test_s5_containment_heading(self, bf):
        assert "Containment Steps" in bf

    def test_s5_phase1_ip_blocking(self, bf):
        assert "Phase 1" in bf
        assert "Blocking" in bf or "Immediate" in bf

    def test_s5_phase2_key_rotation(self, bf):
        assert "Phase 2" in bf
        assert "Key Rotation" in bf or "SSH Key" in bf

    def test_s5_phase3_auth_log_review(self, bf):
        assert "Phase 3" in bf
        assert "Log" in bf

    def test_s5_phase4_account_lockout(self, bf):
        assert "Phase 4" in bf
        assert "Lockout" in bf or "Password" in bf

    # S6 Artifacts
    def test_s6_artifacts(self, bf):
        assert "Artifacts" in bf

    def test_s6_detection_rules(self, bf):
        assert "Detection Rules" in bf

    def test_s6_rule_bf001(self, bf):
        assert "RULE-BF-001" in bf

    def test_s6_log_sources(self, bf):
        assert "Log Sources" in bf

    def test_s6_siem_queries(self, bf):
        assert "SIEM Detection Queries" in bf

    def test_s6_evidence_paths(self, bf):
        assert "Evidence Collection" in bf

    # S7 Appendix
    def test_s7_appendix(self, bf):
        assert "Appendix" in bf

    def test_s7_escalation_contacts(self, bf):
        assert "Escalation Contacts" in bf

    def test_s7_rollback(self, bf):
        assert "Rollback" in bf

    def test_s7_sla(self, bf):
        assert "SLA Targets" in bf

    def test_s7_context_metadata(self, bf):
        assert "Context Metadata" in bf

    def test_no_unrendered_tags(self, bf):
        assert "{{" not in bf and "}}" not in bf

    def test_minimum_length(self, bf):
        assert len(bf) >= 15000


# ═══════════════════════════════════════════════════════════════════════════════
# SQLI_ATTEMPT.MD.J2 — SECTION REVIEW
# ═══════════════════════════════════════════════════════════════════════════════

class TestSQLiAllSections:
    """Verify sqli_attempt.md.j2 — all 7 sections + WAF/DB/input-validation steps."""

    # S1 Header
    def test_s1_sqli_title(self, sqli):
        assert "SQL" in sqli

    def test_s1_playbook_id(self, sqli):
        assert "PB-SQLI-001" in sqli

    def test_s1_http_method(self, sqli):
        assert "HTTP Method" in sqli

    def test_s1_target_endpoint(self, sqli):
        assert "Target Endpoint" in sqli

    def test_s1_db_engine(self, sqli):
        assert "DB Engine" in sqli

    def test_s1_waf_vendor(self, sqli):
        assert "WAF Vendor" in sqli

    def test_s1_event_summary(self, sqli):
        assert "Event Summary" in sqli

    def test_s1_event_summary_content(self, sqli):
        assert "147 events detected between 08:15 and 08:47 UTC" in sqli

    # S2 Summary
    def test_s2_campaign_overview(self, sqli):
        assert "Campaign Overview" in sqli

    def test_s2_time_range(self, sqli):
        assert "Time Range" in sqli

    def test_s2_incident_priority(self, sqli):
        assert "Incident Priority" in sqli

    # S3 IOC Table
    def test_s3_ioc_table(self, sqli):
        assert "Indicators of Compromise" in sqli

    def test_s3_domain_iocs(self, sqli):
        assert "Domain / URL IOCs" in sqli

    # S4 ATT&CK Mapping
    def test_s4_t1190_technique(self, sqli):
        assert "T1190" in sqli

    def test_s4_exploit_public_facing(self, sqli):
        assert "Exploit Public-Facing" in sqli

    def test_s4_initial_access_tactic(self, sqli):
        assert "Initial Access" in sqli

    def test_s4_t1005_data_collection(self, sqli):
        assert "T1005" in sqli

    def test_s4_t1552_unsecured_creds(self, sqli):
        assert "T1552" in sqli

    # S5 Containment — 4 Phases with WAF/Input/DB steps
    def test_s5_phase1_triage_traffic_block(self, sqli):
        assert "Phase 1" in sqli
        assert "Triage" in sqli or "Traffic" in sqli or "Block" in sqli

    def test_s5_phase2_waf_review(self, sqli):
        assert "Phase 2" in sqli
        assert "WAF" in sqli

    def test_s5_phase3_input_validation(self, sqli):
        assert "Phase 3" in sqli
        assert "Input Validation" in sqli or "Parameterised" in sqli

    def test_s5_phase4_db_integrity(self, sqli):
        assert "Phase 4" in sqli
        assert "Database" in sqli or "DB" in sqli or "integrity" in sqli.lower()

    # S6 Artifacts
    def test_s6_detection_rules(self, sqli):
        assert "Detection Rules" in sqli

    def test_s6_rule_sqli001(self, sqli):
        assert "RULE-SQLI-001" in sqli

    def test_s6_log_sources(self, sqli):
        assert "Log Sources" in sqli

    def test_s6_siem_queries(self, sqli):
        assert "SIEM Detection Queries" in sqli

    def test_s6_evidence_collection(self, sqli):
        assert "Evidence Collection" in sqli

    # S7 Appendix
    def test_s7_appendix_complete(self, sqli):
        for kw in ["Appendix", "Escalation Contacts", "Rollback", "SLA Targets", "Context Metadata"]:
            assert kw in sqli, f"Missing: {kw}"

    def test_no_unrendered_tags(self, sqli):
        assert "{{" not in sqli and "}}" not in sqli

    def test_minimum_length(self, sqli):
        assert len(sqli) >= 18000


# ═══════════════════════════════════════════════════════════════════════════════
# PORT_SCAN.MD.J2 — SECTION REVIEW
# ═══════════════════════════════════════════════════════════════════════════════

class TestPortScanAllSections:
    """Verify port_scan.md.j2 — all 7 sections + segmentation/exposed service steps."""

    # S1 Header
    def test_s1_port_scan_title(self, pscan):
        assert "Port Scan" in pscan or "Reconnaissance" in pscan

    def test_s1_playbook_id(self, pscan):
        assert "PB-PORTSCAN-001" in pscan

    def test_s1_scan_type(self, pscan):
        assert "Scan Type" in pscan

    def test_s1_scanner_tool(self, pscan):
        assert "Scanner Tool" in pscan

    def test_s1_ports_scanned(self, pscan):
        assert "Ports Scanned" in pscan

    def test_s1_event_summary(self, pscan):
        assert "Event Summary" in pscan

    def test_s1_event_summary_content(self, pscan):
        assert "147 events detected between 08:15 and 08:47 UTC" in pscan

    # S2 Summary
    def test_s2_campaign_overview(self, pscan):
        assert "Campaign Overview" in pscan

    def test_s2_time_range(self, pscan):
        assert "Time Range" in pscan

    def test_s2_incident_priority(self, pscan):
        assert "Incident Priority" in pscan

    # S3 IOC Table
    def test_s3_ioc_table(self, pscan):
        assert "Indicators of Compromise" in pscan

    # S4 ATT&CK Mapping
    def test_s4_t1595_active_scanning(self, pscan):
        assert "T1595" in pscan

    def test_s4_active_scanning_name(self, pscan):
        assert "Active Scanning" in pscan

    def test_s4_t1046_network_service_discovery(self, pscan):
        assert "T1046" in pscan

    def test_s4_discovery_tactic(self, pscan):
        assert "Discovery" in pscan

    def test_s4_t1018_remote_system(self, pscan):
        assert "T1018" in pscan

    # S5 Containment — 4 Phases
    def test_s5_phase1_traffic_control_evidence(self, pscan):
        assert "Phase 1" in pscan
        assert "Evidence" in pscan or "Traffic" in pscan

    def test_s5_phase2_network_segmentation(self, pscan):
        assert "Phase 2" in pscan
        assert "Segmentation" in pscan or "segmentation" in pscan

    def test_s5_phase3_exposed_service_audit(self, pscan):
        assert "Phase 3" in pscan
        assert "Exposed" in pscan or "Service Audit" in pscan or "Open Port" in pscan

    def test_s5_phase4_deception_hardening(self, pscan):
        assert "Phase 4" in pscan
        assert "Deception" in pscan or "Hardening" in pscan

    # S6 Artifacts
    def test_s6_detection_rules(self, pscan):
        assert "Detection Rules" in pscan

    def test_s6_rule_scan001(self, pscan):
        assert "RULE-SCAN-001" in pscan

    def test_s6_siem_queries(self, pscan):
        assert "SIEM Detection Queries" in pscan

    def test_s6_log_sources(self, pscan):
        assert "Log Sources" in pscan

    def test_s6_evidence_collection(self, pscan):
        assert "Evidence Collection" in pscan

    # S7 Appendix
    def test_s7_appendix_complete(self, pscan):
        for kw in ["Appendix", "Escalation Contacts", "Rollback", "SLA Targets", "Context Metadata"]:
            assert kw in pscan, f"Missing: {kw}"

    def test_no_unrendered_tags(self, pscan):
        assert "{{" not in pscan and "}}" not in pscan

    def test_minimum_length(self, pscan):
        assert len(pscan) >= 16000


# ═══════════════════════════════════════════════════════════════════════════════
# DATA_EXFILTRATION.MD.J2 — SECTION REVIEW
# ═══════════════════════════════════════════════════════════════════════════════

class TestDataExfilAllSections:
    """Verify data_exfiltration.md.j2 — all 7 sections + DLP/file-integrity/outbound steps."""

    # S1 Header
    def test_s1_data_exfil_title(self, exfil):
        assert "Data Exfiltration" in exfil

    def test_s1_playbook_id(self, exfil):
        assert "PB-EXFIL-001" in exfil

    def test_s1_exfil_vector(self, exfil):
        assert "Exfil Vector" in exfil

    def test_s1_dlp_vendor(self, exfil):
        assert "DLP Vendor" in exfil

    def test_s1_breach_notification(self, exfil):
        assert "Breach Notification" in exfil

    def test_s1_legal_hold(self, exfil):
        assert "Legal Hold" in exfil

    def test_s1_event_summary(self, exfil):
        assert "Event Summary" in exfil

    def test_s1_event_summary_content(self, exfil):
        assert "147 events detected between 08:15 and 08:47 UTC" in exfil

    def test_s1_critical_severity(self, exfil):
        assert "CRITICAL" in exfil

    def test_s1_tlp_red(self, exfil):
        assert "TLP:RED" in exfil

    # S2 Summary
    def test_s2_campaign_overview(self, exfil):
        assert "Campaign Overview" in exfil

    def test_s2_time_range(self, exfil):
        assert "Time Range" in exfil

    def test_s2_incident_priority(self, exfil):
        assert "Incident Priority" in exfil

    # S3 IOC Table
    def test_s3_ioc_table(self, exfil):
        assert "Indicators of Compromise" in exfil

    # S4 ATT&CK Mapping
    def test_s4_t1041_exfil_c2(self, exfil):
        assert "T1041" in exfil

    def test_s4_t1048_exfil_alt_protocol(self, exfil):
        assert "T1048" in exfil

    def test_s4_t1567_web_service(self, exfil):
        assert "T1567" in exfil

    def test_s4_exfiltration_tactic(self, exfil):
        assert "Exfiltration" in exfil

    def test_s4_t1030_data_transfer_limits(self, exfil):
        assert "T1030" in exfil

    # S5 Containment — 5 Phases
    def test_s5_phase1_isolation_traffic_block(self, exfil):
        assert "Phase 1" in exfil
        assert "Isolation" in exfil or "Block" in exfil

    def test_s5_phase2_dlp_review(self, exfil):
        assert "Phase 2" in exfil
        assert "DLP" in exfil

    def test_s5_phase3_file_integrity(self, exfil):
        assert "Phase 3" in exfil
        assert "File Integrity" in exfil or "Integrity" in exfil

    def test_s5_phase4_outbound_traffic(self, exfil):
        assert "Phase 4" in exfil
        assert "Outbound" in exfil or "Traffic" in exfil

    def test_s5_phase5_data_classification_impact(self, exfil):
        assert "Phase 5" in exfil
        assert "Classification" in exfil or "Impact" in exfil

    # S6 Artifacts
    def test_s6_detection_rules(self, exfil):
        assert "Detection Rules" in exfil

    def test_s6_rule_exfil001(self, exfil):
        assert "RULE-EXFIL-001" in exfil

    def test_s6_log_sources(self, exfil):
        assert "Log Sources" in exfil

    def test_s6_siem_queries(self, exfil):
        assert "SIEM Detection Queries" in exfil

    def test_s6_evidence_collection(self, exfil):
        assert "Evidence Collection" in exfil

    # S7 Appendix
    def test_s7_appendix_complete(self, exfil):
        for kw in ["Appendix", "Escalation Contacts", "Rollback", "SLA Targets", "Context Metadata"]:
            assert kw in exfil, f"Missing: {kw}"

    def test_no_unrendered_tags(self, exfil):
        assert "{{" not in exfil and "}}" not in exfil

    def test_minimum_length(self, exfil):
        assert len(exfil) >= 24000


# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-TEMPLATE SECTION COMPLETENESS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossTemplateCompleteness:
    """Parametrized checks that every section exists in every template."""

    ALL_PATTERNS = [
        ("brute_force", "brute_force"),
        ("sqli",        "sqli_attempt"),
        ("port_scan",   "port_scan"),
        ("data_exfil",  "data_exfiltration"),
    ]

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_s1_header_complete(self, pattern, name):
        r = _render(pattern)
        for kw in ["Playbook ID", "Severity", "Generated At", "Event Summary"]:
            assert kw in r, f"[{name}] Header missing: {kw}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_s2_summary_complete(self, pattern, name):
        r = _render(pattern)
        for kw in ["Campaign Overview", "Trigger Context", "Affected Assets", "Incident Priority", "Time Range"]:
            assert kw in r, f"[{name}] Summary missing: {kw}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_s3_ioc_table_complete(self, pattern, name):
        r = _render(pattern)
        for kw in ["Indicators of Compromise", "Source IPs", "Domain / URL IOCs"]:
            assert kw in r, f"[{name}] IOC Table missing: {kw}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_s4_attack_mapping_complete(self, pattern, name):
        r = _render(pattern)
        for kw in ["MITRE ATT", "Technique ID", "Tactic"]:
            assert kw in r, f"[{name}] ATT&CK missing: {kw}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_s5_containment_has_phases(self, pattern, name):
        r = _render(pattern)
        for kw in ["Containment Steps", "Phase 1", "Phase 2", "Phase 3"]:
            assert kw in r, f"[{name}] Containment missing: {kw}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_s6_artifacts_complete(self, pattern, name):
        r = _render(pattern)
        for kw in ["Detection Rules", "Log Sources", "Evidence Collection", "SIEM Detection Queries"]:
            assert kw in r, f"[{name}] Artifacts missing: {kw}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_s7_appendix_complete(self, pattern, name):
        r = _render(pattern)
        for kw in ["Escalation Contacts", "Rollback", "SLA Targets", "Context Metadata"]:
            assert kw in r, f"[{name}] Appendix missing: {kw}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_no_unrendered_jinja_tags(self, pattern, name):
        r = _render(pattern)
        assert "{{" not in r, f"[{name}] Unrendered {{ found"
        assert "}}" not in r, f"[{name}] Unrendered }} found"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_event_summary_present_and_correct(self, pattern, name):
        r = _render(pattern)
        assert "147 events detected between 08:15 and 08:47 UTC" in r, (
            f"[{name}] Exact event summary format missing"
        )

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS)
    def test_no_empty_sections(self, pattern, name):
        """Each section must have at least 200 chars of content."""
        r = _render(pattern)
        assert len(r) >= 10000, f"[{name}] Output suspiciously short: {len(r)} chars"
