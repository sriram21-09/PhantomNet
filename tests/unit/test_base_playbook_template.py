"""
tests/unit/test_base_playbook_template.py
------------------------------------------
Unit tests for sentinel/templates/base_playbook.md.j2

Validates:
- All 7 sections are present in the rendered output
- Header fields (title, severity badge, playbook_id, timestamps)
- Summary section (campaign overview, trigger context, affected assets)
- IOC table (single IP, multiple IOCs list, hash table, domain IOCs)
- ATT&CK mapping for each of the 4 known attack patterns + generic fallback
- Containment steps rendered for each attack pattern (all 3 phases)
- Artifacts section (detection rules, log sources, SIEM queries, evidence paths)
- Appendix (escalation contacts, rollback, SLA table, metadata block)
- All Jinja2 default values applied when optional keys are omitted
"""

import pytest
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader

import os

TEMPLATE_NAME = "base_playbook.md.j2"

# ── Fixture ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def env():
    """Jinja2 environment pointed at sentinel/templates/."""
    templates_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "backend", "sentinel", "templates"
    )
    return Environment(
        loader=FileSystemLoader(os.path.abspath(templates_dir)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


@pytest.fixture(scope="module")
def template(env):
    return env.get_template(TEMPLATE_NAME)


def render(template, **ctx):
    """Helper: render template with given context."""
    ctx.setdefault("generated_at", "2026-06-18T08:00:00Z")
    return template.render(**ctx)


# ── Template existence ────────────────────────────────────────────────────

class TestTemplateExists:
    def test_template_loads(self, template):
        assert template is not None

    def test_template_name(self, template):
        assert template.name == TEMPLATE_NAME


# ── Section 1: Header ─────────────────────────────────────────────────────

class TestHeaderSection:
    def test_title_rendered(self, template):
        out = render(template, title="Brute Force Response", attack_pattern="brute_force", severity="HIGH")
        assert "# 🛡️ Brute Force Response" in out

    def test_default_title_used(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "Incident Response Playbook" in out

    def test_severity_critical_badge(self, template):
        out = render(template, attack_pattern="brute_force", severity="CRITICAL")
        assert "🔴 **CRITICAL**" in out

    def test_severity_high_badge(self, template):
        out = render(template, attack_pattern="brute_force", severity="HIGH")
        assert "🟠 **HIGH**" in out

    def test_severity_medium_badge(self, template):
        out = render(template, attack_pattern="port_scan", severity="MEDIUM")
        assert "🟡 **MEDIUM**" in out

    def test_severity_low_badge(self, template):
        out = render(template, attack_pattern="port_scan", severity="LOW")
        assert "🟢 **LOW**" in out

    def test_generated_at_rendered(self, template):
        ts = "2026-06-18T08:00:00Z"
        out = render(template, attack_pattern="brute_force", generated_at=ts)
        assert ts in out

    def test_classification_default(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "TLP:AMBER" in out

    def test_custom_classification(self, template):
        out = render(template, attack_pattern="brute_force", classification="TLP:RED")
        assert "TLP:RED" in out

    def test_version_default(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "1.0.0" in out

    def test_generator_line_present(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "PhantomNet Sentinel" in out


# ── Section 2: Summary ───────────────────────────────────────────────────

class TestSummarySection:
    def test_summary_heading(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "## 📋 Summary" in out

    def test_default_campaign_overview(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "automated detection triggered this playbook" in out

    def test_custom_campaign_overview(self, template):
        out = render(template, attack_pattern="brute_force",
                     campaign_overview="Coordinated SSH brute force from Eastern Europe.")
        assert "Coordinated SSH brute force" in out

    def test_trigger_context_table(self, template):
        out = render(template, attack_pattern="brute_force",
                     trigger_type="failed_login_threshold",
                     source_ip="10.0.0.1")
        assert "failed_login_threshold" in out
        assert "10.0.0.1" in out

    def test_affected_assets_list(self, template):
        out = render(template, attack_pattern="brute_force",
                     affected_assets=["192.168.1.10", "192.168.1.11"])
        assert "192.168.1.10" in out
        assert "192.168.1.11" in out

    def test_affected_assets_default_fallback(self, template):
        out = render(template, attack_pattern="brute_force",
                     target_ip="192.168.2.99")
        assert "192.168.2.99" in out

    def test_incident_priority_table(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "Confidentiality Impact" in out
        assert "Blast Radius" in out


# ── Section 3: IOC Table ─────────────────────────────────────────────────

class TestIOCTableSection:
    def test_ioc_heading(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "## 🔍 Indicators of Compromise" in out

    def test_single_source_ip_default(self, template):
        out = render(template, attack_pattern="brute_force", source_ip="1.2.3.4")
        assert "1.2.3.4" in out

    def test_iocs_list_rendered(self, template):
        iocs = [
            {"ip": "5.5.5.5", "ports": "22,80", "protocol": "TCP",
             "hit_count": 42, "threat_intel": "⚠️ Known scanner",
             "first_seen": "2026-06-18T07:00Z", "last_seen": "2026-06-18T08:00Z"},
            {"ip": "6.6.6.6", "ports": "443", "protocol": "TCP",
             "hit_count": 7, "threat_intel": "✅ Clean",
             "first_seen": "2026-06-18T07:30Z", "last_seen": "2026-06-18T07:45Z"},
        ]
        out = render(template, attack_pattern="distributed_attack", iocs=iocs)
        assert "5.5.5.5" in out
        assert "Known scanner" in out
        assert "6.6.6.6" in out

    def test_ioc_hashes_rendered(self, template):
        hashes = [{"type": "SHA256", "value": "abc123def456"}]
        out = render(template, attack_pattern="brute_force", ioc_hashes=hashes)
        assert "abc123def456" in out

    def test_ioc_hashes_missing_warning(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "No file hashes collected" in out

    def test_domain_iocs_rendered(self, template):
        domains = [{"domain": "evil.example.com", "resolved_ip": "9.9.9.9", "category": "C2"}]
        out = render(template, attack_pattern="brute_force", ioc_domains=domains)
        assert "evil.example.com" in out
        assert "C2" in out

    def test_domain_iocs_missing_info(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "No domain IOCs captured" in out


# ── Section 4: ATT&CK Mapping ─────────────────────────────────────────────

class TestATTACKMappingSection:
    def test_attack_heading(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "## 🎯 MITRE ATT" in out

    def test_brute_force_techniques(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "T1110" in out
        assert "Brute Force" in out
        assert "Credential Access" in out

    def test_failed_login_maps_to_brute_force(self, template):
        out = render(template, attack_pattern="failed_login")
        assert "T1110" in out

    def test_port_scan_techniques(self, template):
        out = render(template, attack_pattern="port_scan")
        assert "T1595" in out
        assert "Active Scanning" in out
        assert "Reconnaissance" in out

    def test_scan_maps_to_port_scan(self, template):
        out = render(template, attack_pattern="scan")
        assert "T1595" in out

    def test_credential_reuse_techniques(self, template):
        out = render(template, attack_pattern="credential_reuse")
        assert "T1078" in out
        assert "Valid Accounts" in out

    def test_honeytoken_maps_to_credential_reuse(self, template):
        out = render(template, attack_pattern="honeytoken")
        assert "T1552" in out

    def test_distributed_attack_techniques(self, template):
        out = render(template, attack_pattern="distributed_attack")
        assert "T1583" in out
        assert "T1498" in out

    def test_distributed_maps_to_distributed_attack(self, template):
        out = render(template, attack_pattern="distributed")
        assert "T1498" in out

    def test_generic_fallback_technique(self, template):
        out = render(template, attack_pattern="custom_unknown",
                     attack_techniques=[
                         {"id": "T9999", "name": "Custom Technique",
                          "tactic": "Impact", "description": "Test technique."}
                     ])
        assert "T9999" in out
        assert "Custom Technique" in out

    def test_mitre_reference_link(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "attack.mitre.org" in out


# ── Section 5: Containment Steps ─────────────────────────────────────────

class TestContainmentSection:
    def test_containment_heading(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "## 🚨 Containment Steps" in out

    def test_brute_force_phase1(self, template):
        out = render(template, attack_pattern="brute_force", source_ip="1.2.3.4")
        assert "Block attacker IP" in out
        assert "1.2.3.4" in out
        assert "Enable tarpit" in out

    def test_brute_force_phase2(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "Query threat intelligence" in out
        assert "Pull authentication logs" in out

    def test_brute_force_phase3(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "Create incident ticket" in out
        assert "Enable MFA" in out

    def test_port_scan_phase1(self, template):
        out = render(template, attack_pattern="port_scan", source_ip="7.7.7.7")
        assert "Start packet capture" in out
        assert "Deploy honeypots" in out
        assert "7.7.7.7" in out

    def test_port_scan_phase2(self, template):
        out = render(template, attack_pattern="port_scan")
        assert "Analyse scan pattern" in out
        assert "Alert SOC" in out

    def test_port_scan_phase3(self, template):
        out = render(template, attack_pattern="port_scan")
        assert "Patch exposed services" in out

    def test_credential_reuse_critical_alert(self, template):
        out = render(template, attack_pattern="credential_reuse",
                     source_ip="8.8.8.8", token_id="htkn-001")
        assert "CISO Alert" in out
        assert "htkn-001" in out
        assert "8.8.8.8" in out

    def test_credential_reuse_phase2(self, template):
        out = render(template, attack_pattern="honeytoken")
        assert "Full system scan" in out
        assert "Capture forensic" in out

    def test_credential_reuse_phase3(self, template):
        out = render(template, attack_pattern="credential_reuse")
        assert "Rotate all shared secrets" in out
        assert "Deploy new honeytokens" in out

    def test_distributed_attack_phase1(self, template):
        out = render(template, attack_pattern="distributed_attack")
        assert "Correlate events" in out
        assert "Escalate defensive posture" in out

    def test_distributed_attack_phase2(self, template):
        out = render(template, attack_pattern="distributed")
        assert "Block all campaign IPs" in out
        assert "Export IOCs" in out

    def test_distributed_attack_phase3(self, template):
        out = render(template, attack_pattern="distributed_attack")
        assert "Generate campaign report" in out
        assert "Share IOCs with ISAC" in out

    def test_generic_containment_fallback(self, template):
        out = render(template, attack_pattern="unknown_custom")
        assert "Identify and isolate" in out
        assert "Preserve evidence" in out

    def test_checkboxes_present(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "- [ ]" in out


# ── Section 6: Artifacts ─────────────────────────────────────────────────

class TestArtifactsSection:
    def test_artifacts_heading(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "## 📁 Artifacts" in out

    def test_detection_rules_default(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "RULE-AUTO" in out

    def test_detection_rules_list(self, template):
        rules = [{"id": "RULE-001", "name": "SSH Brute Force", "source": "Suricata", "status": "✅ Active"}]
        out = render(template, attack_pattern="brute_force", detection_rules=rules)
        assert "RULE-001" in out
        assert "SSH Brute Force" in out
        assert "Suricata" in out

    def test_log_sources_table(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "Auth Logs" in out
        assert "Network Traffic" in out
        assert "Honeypot Logs" in out
        assert "Firewall Logs" in out

    def test_evidence_paths_default(self, template):
        out = render(template, attack_pattern="brute_force", source_ip="1.2.3.4")
        assert "reports/incidents" in out
        assert "1.2.3.4" in out

    def test_custom_evidence_paths(self, template):
        out = render(template, attack_pattern="brute_force",
                     evidence_paths=["/data/incidents/2026/", "/forensics/host1/"])
        assert "/data/incidents/2026/" in out
        assert "/forensics/host1/" in out

    def test_siem_query_brute_force(self, template):
        out = render(template, attack_pattern="brute_force", source_ip="1.2.3.4")
        assert "failed_login" in out
        assert "1.2.3.4" in out

    def test_siem_query_port_scan(self, template):
        out = render(template, attack_pattern="port_scan", source_ip="5.6.7.8")
        assert "dest_port" in out
        assert "5.6.7.8" in out

    def test_siem_query_honeytoken(self, template):
        out = render(template, attack_pattern="honeytoken", token_id="htkn-007")
        assert "token_id" in out
        assert "htkn-007" in out

    def test_siem_query_distributed(self, template):
        out = render(template, attack_pattern="distributed_attack")
        assert "distinct_sources" in out


# ── Section 7: Appendix ──────────────────────────────────────────────────

class TestAppendixSection:
    def test_appendix_heading(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "## 📎 Appendix" in out

    def test_escalation_contacts_table(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "Incident Commander" in out
        assert "CISO" in out
        assert "Forensics Team" in out

    def test_custom_escalation_contacts(self, template):
        out = render(template, attack_pattern="brute_force",
                     ic_name="Alice Smith", ic_contact="alice@corp.com")
        assert "Alice Smith" in out
        assert "alice@corp.com" in out

    def test_rollback_default_steps(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "Unblock IP" in out
        assert "Reconnect host" in out

    def test_custom_rollback_steps(self, template):
        steps = [{"name": "Remove ACL", "description": "Delete temporary ACL rule from switch."}]
        out = render(template, attack_pattern="brute_force", rollback_steps=steps)
        assert "Remove ACL" in out
        assert "Delete temporary ACL rule" in out

    def test_sla_targets_table(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "Time to Detect" in out
        assert "Time to Respond" in out
        assert "Time to Contain" in out
        assert "Time to Recover" in out

    def test_custom_sla_targets(self, template):
        out = render(template, attack_pattern="brute_force",
                     ttd_target="< 1 minute", ttr_target="< 5 minutes")
        assert "< 1 minute" in out
        assert "< 5 minutes" in out

    def test_metadata_yaml_block(self, template):
        out = render(template, attack_pattern="brute_force",
                     severity="HIGH", generated_at="2026-06-18T08:00:00Z")
        assert "playbook_id:" in out
        assert "attack_pattern:" in out
        assert "severity:" in out

    def test_footer_link(self, template):
        out = render(template, attack_pattern="brute_force")
        assert "PhantomNet Sentinel" in out
        assert "github.com/sriram21-09/PhantomNet" in out
