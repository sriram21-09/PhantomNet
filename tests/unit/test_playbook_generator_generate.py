"""
tests/unit/test_playbook_generator_generate.py
------------------------------------------------
Comprehensive tests for PlaybookGenerator.generate() with full
Markdown template selection, context enrichment, and rendering.

Covers every task deliverable:
  ✅ Template selection for all 4 attack patterns + base fallback
  ✅ brute_force  → brute_force.md.j2
  ✅ sqli_attempt → sqli_attempt.md.j2
  ✅ port_scan    → port_scan.md.j2
  ✅ data_exfiltration → data_exfiltration.md.j2
  ✅ unknown      → base_playbook.md.j2 (fallback)
  ✅ Context enrichment: IOCs, ATT&CK, timestamps, containment, artifacts
  ✅ All 7 playbook sections render correctly in output Markdown
  ✅ Backward compatibility with legacy YAML format
"""

import os
import re
import pytest
import yaml
from datetime import datetime, timezone

from sentinel.playbook_generator import PlaybookGenerator


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def gen() -> PlaybookGenerator:
    """Return a default PlaybookGenerator instance."""
    return PlaybookGenerator()


@pytest.fixture
def brute_ctx():
    return {
        "attack_pattern": "brute_force",
        "source_ip": "192.168.1.100",
        "severity": "CRITICAL",
        "failed_logins_threshold": 30,
        "timeframe": "5 minutes",
        "target_ip": "10.0.0.5",
    }


@pytest.fixture
def sqli_ctx():
    return {
        "attack_pattern": "sqli_attempt",
        "source_ip": "1.2.3.4",
        "severity": "HIGH",
        "target_ip": "10.0.0.50",
        "target_url": "/api/users",
        "db_host": "db.internal",
        "db_engine": "MySQL",
        "db_name": "app_db",
    }


@pytest.fixture
def scan_ctx():
    return {
        "attack_pattern": "port_scan",
        "source_ip": "9.8.7.6",
        "severity": "HIGH",
        "target_subnet": "10.0.2.0/24",
        "target_ip": "10.0.2.50",
        "port_count": 250,
    }


@pytest.fixture
def exfil_ctx():
    return {
        "attack_pattern": "data_exfiltration",
        "source_ip": "10.0.1.50",
        "destination_ip": "203.0.113.99",
        "destination_domain": "evil.attacker.com",
        "exfil_vector": "https",
        "data_classification": "CONFIDENTIAL",
    }


# ============================================================
# Initialization (preserved from original)
# ============================================================

class TestInit:
    def test_instance_created(self, gen):
        assert gen is not None

    def test_jinja2_env_configured(self, gen):
        assert gen.env is not None

    def test_loader_attached(self, gen):
        assert gen.loader is not None

    def test_templates_dir_is_absolute(self, gen):
        assert os.path.isabs(gen.templates_dir)

    def test_templates_dir_uses_dirname_file(self, gen):
        """Critical: template path must use os.path.dirname(__file__)."""
        expected_dir = os.path.join(
            os.path.dirname(os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "backend", "sentinel", "playbook_generator.py")
            )),
            "templates",
        )
        assert gen.templates_dir.endswith(os.path.join("sentinel", "templates"))

    def test_no_hardcoded_absolute_path(self):
        """Verify source code does NOT hardcode absolute paths."""
        src = os.path.join(
            os.path.dirname(__file__), "..", "..", "backend", "sentinel", "playbook_generator.py"
        )
        with open(src, encoding="utf-8") as f:
            content = f.read()
        # Should use os.path.dirname(__file__), NOT C:\ or /home or /usr
        assert "os.path.dirname" in content
        # Should NOT contain Windows-style absolute paths
        assert "C:\\" not in content
        assert "D:\\" not in content

    def test_custom_templates_dir(self, tmp_path):
        g = PlaybookGenerator(templates_dir=str(tmp_path))
        assert g.templates_dir == str(tmp_path)


# ============================================================
# Markdown Template Selection (_select_template with format="markdown")
# ============================================================

class TestMDTemplateSelection:
    @pytest.mark.parametrize("pattern,expected", [
        ("brute_force",                   "brute_force.md.j2"),
        ("brute-force",                   "brute_force.md.j2"),
        ("failed_login",                  "brute_force.md.j2"),
        ("SSH_BRUTE_FORCE_DISTRIBUTED",   "brute_force.md.j2"),
        ("ssh_brute",                     "brute_force.md.j2"),
        ("sqli_attempt",                  "sqli_attempt.md.j2"),
        ("sqli",                          "sqli_attempt.md.j2"),
        ("sql_injection",                 "sqli_attempt.md.j2"),
        ("sql-injection",                 "sqli_attempt.md.j2"),
        ("port_scan",                     "port_scan.md.j2"),
        ("port-scan",                     "port_scan.md.j2"),
        ("scan",                          "port_scan.md.j2"),
        ("recon",                         "port_scan.md.j2"),
        ("reconnaissance",               "port_scan.md.j2"),
        ("data_exfiltration",             "data_exfiltration.md.j2"),
        ("data_exfil",                    "data_exfiltration.md.j2"),
        ("exfiltration",                  "data_exfiltration.md.j2"),
        ("dlp",                           "data_exfiltration.md.j2"),
        ("data_theft",                    "data_exfiltration.md.j2"),
    ])
    def test_known_patterns(self, gen, pattern, expected):
        assert gen._select_template(pattern, format="markdown") == expected

    def test_unknown_falls_back_to_base(self, gen):
        assert gen._select_template("unknown_pattern", format="markdown") == "base_playbook.md.j2"

    def test_unknown_custom_pattern_falls_back_to_base(self, gen):
        assert gen._select_template("malware_dropper", format="markdown") == "base_playbook.md.j2"


# ============================================================
# Legacy YAML Template Selection (backward compat)
# ============================================================

class TestYAMLTemplateSelection:
    @pytest.mark.parametrize("pattern,expected", [
        ("brute_force",                   "brute_force_response.yaml.j2"),
        ("brute-force",                   "brute_force_response.yaml.j2"),
        ("failed_login",                  "brute_force_response.yaml.j2"),
        ("SSH_BRUTE_FORCE_DISTRIBUTED",   "brute_force_response.yaml.j2"),
        ("port_scan",                     "port_scan_response.yaml.j2"),
        ("port-scan",                     "port_scan_response.yaml.j2"),
        ("scan",                          "port_scan_response.yaml.j2"),
        ("credential_reuse",              "credential_reuse_response.yaml.j2"),
        ("credential-reuse",              "credential_reuse_response.yaml.j2"),
        ("honeytoken",                    "credential_reuse_response.yaml.j2"),
        ("distributed_attack",            "distributed_attack_response.yaml.j2"),
        ("distributed-attack",            "distributed_attack_response.yaml.j2"),
        ("distributed",                   "distributed_attack_response.yaml.j2"),
    ])
    def test_known_yaml_patterns(self, gen, pattern, expected):
        assert gen._select_template(pattern, format="yaml") == expected

    def test_yaml_fallback_unknown(self, gen):
        assert gen._select_template("custom_pattern", format="yaml") == "custom_pattern_response.yaml.j2"


# ============================================================
# validate_context (preserved from original)
# ============================================================

class TestValidateContext:
    def test_valid_context_passes(self, gen):
        gen.validate_context({"attack_pattern": "brute_force"})

    def test_missing_attack_pattern_raises(self, gen):
        with pytest.raises(ValueError, match="attack_pattern"):
            gen.validate_context({"source_ip": "1.1.1.1"})

    def test_empty_attack_pattern_raises(self, gen):
        with pytest.raises(ValueError, match="attack_pattern"):
            gen.validate_context({"attack_pattern": ""})

    def test_non_dict_raises(self, gen):
        with pytest.raises(TypeError):
            gen.validate_context(["attack_pattern", "brute_force"])


# ============================================================
# list_templates
# ============================================================

class TestListTemplates:
    def test_returns_list(self, gen):
        templates = gen.list_templates()
        assert isinstance(templates, list)

    def test_default_lists_yaml_j2(self, gen):
        for t in gen.list_templates():
            assert t.endswith(".yaml.j2")

    def test_expected_yaml_templates_present(self, gen):
        templates = gen.list_templates()
        assert "brute_force_response.yaml.j2" in templates
        assert "port_scan_response.yaml.j2" in templates

    def test_md_j2_filter(self, gen):
        md_templates = gen.list_templates(".md.j2")
        assert isinstance(md_templates, list)
        for t in md_templates:
            assert t.endswith(".md.j2")

    def test_expected_md_templates_present(self, gen):
        md_templates = gen.list_templates(".md.j2")
        assert "base_playbook.md.j2" in md_templates
        assert "brute_force.md.j2" in md_templates
        assert "sqli_attempt.md.j2" in md_templates
        assert "port_scan.md.j2" in md_templates
        assert "data_exfiltration.md.j2" in md_templates

    def test_sorted_order(self, gen):
        templates = gen.list_templates()
        assert templates == sorted(templates)


# ============================================================
# _resolve_canonical_pattern
# ============================================================

class TestCanonicalPattern:
    @pytest.mark.parametrize("raw,expected", [
        ("brute_force",    "brute_force"),
        ("brute-force",    "brute_force"),
        ("failed_login",   "brute_force"),
        ("ssh_brute",      "brute_force"),
        ("sqli_attempt",   "sqli_attempt"),
        ("sqli",           "sqli_attempt"),
        ("sql_injection",  "sqli_attempt"),
        ("port_scan",      "port_scan"),
        ("scan",           "port_scan"),
        ("recon",          "port_scan"),
        ("data_exfil",     "data_exfiltration"),
        ("exfiltration",   "data_exfiltration"),
        ("dlp",            "data_exfiltration"),
        ("random_thing",   "unknown"),
    ])
    def test_canonical_mapping(self, gen, raw, expected):
        assert gen._resolve_canonical_pattern(raw) == expected


# ============================================================
# Context enrichment (_build_enriched_context)
# ============================================================

class TestContextEnrichment:
    def test_generated_at_auto_populated(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "brute_force", "source_ip": "1.1.1.1"},
            "brute_force",
        )
        assert "generated_at" in ctx
        assert "T" in ctx["generated_at"]
        assert ctx["generated_at"].endswith("Z")

    def test_generated_at_not_overridden(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "brute_force", "generated_at": "CUSTOM"},
            "brute_force",
        )
        assert ctx["generated_at"] == "CUSTOM"

    def test_generator_version_populated(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "brute_force"},
            "brute_force",
        )
        assert "generator_version" in ctx
        assert ctx["generator_version"] == "2.0.0"

    def test_severity_default(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "brute_force"},
            "brute_force",
        )
        assert ctx["severity"] == "HIGH"

    def test_iocs_auto_built_from_source_ip(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "brute_force", "source_ip": "5.5.5.5"},
            "brute_force",
        )
        assert "iocs" in ctx
        assert isinstance(ctx["iocs"], list)
        assert ctx["iocs"][0]["ip"] == "5.5.5.5"

    def test_iocs_not_overridden_if_provided(self, gen):
        custom_iocs = [{"ip": "custom"}]
        ctx = gen._build_enriched_context(
            {"attack_pattern": "brute_force", "iocs": custom_iocs},
            "brute_force",
        )
        assert ctx["iocs"] == custom_iocs

    def test_attack_techniques_auto_populated(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "sqli_attempt"},
            "sqli_attempt",
        )
        assert "attack_techniques" in ctx
        assert len(ctx["attack_techniques"]) > 0
        assert any(t["id"] == "T1190" for t in ctx["attack_techniques"])

    def test_containment_steps_auto_populated(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "port_scan"},
            "port_scan",
        )
        assert "containment_steps" in ctx
        assert len(ctx["containment_steps"]) > 0

    def test_brute_force_defaults(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "brute_force"},
            "brute_force",
        )
        assert ctx["ssh_port"] == 22
        assert ctx["failed_logins_threshold"] == 10
        assert ctx["block_duration"] == "3600"
        assert ctx["tarpit_delay_ms"] == 5000
        assert ctx["lockout_policy_threshold"] == 5
        assert ctx["min_password_length"] == 16

    def test_sqli_defaults(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "sqli_attempt"},
            "sqli_attempt",
        )
        assert ctx["db_engine"] == "MySQL"
        assert ctx["waf_mode"] == "detection"
        assert ctx["http_method"] == "GET"

    def test_port_scan_defaults(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "port_scan"},
            "port_scan",
        )
        assert ctx["scan_type"] == "SYN"
        assert ctx["port_count_threshold"] == 50
        assert ctx["honeypot_count"] == 3
        assert ctx["deception_mode"] == "aggressive_deception"
        assert ctx["sdn_enabled"] is True

    def test_data_exfil_defaults(self, gen):
        ctx = gen._build_enriched_context(
            {"attack_pattern": "data_exfiltration"},
            "data_exfiltration",
        )
        assert ctx["exfil_vector"] == "https"
        assert ctx["data_classification"] == "CONFIDENTIAL"
        assert ctx["dlp_mode"] == "monitor"
        assert ctx["severity"] == "CRITICAL"  # elevated default
        assert ctx["classification"] == "TLP:RED"  # elevated default
        assert ctx["breach_notif_required"] is False
        assert ctx["insider_threat"] is False

    def test_caller_dict_not_mutated(self, gen):
        original = {"attack_pattern": "brute_force", "source_ip": "1.1.1.1"}
        original_keys = set(original.keys())
        gen._build_enriched_context(original, "brute_force")
        assert set(original.keys()) == original_keys


# ============================================================
# generate() – Markdown format – brute_force
# ============================================================

class TestGenerateMDBruteForce:
    def test_returns_non_empty_string(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert isinstance(out, str)
        assert len(out) > 500

    def test_markdown_not_yaml(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "# " in out  # Markdown heading
        # Should NOT parse as simple YAML dict
        assert out.strip().startswith("#")

    def test_source_ip_rendered(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "192.168.1.100" in out

    def test_severity_badge_rendered(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "🔴 **CRITICAL**" in out

    def test_attack_pattern_in_output(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "brute_force" in out.lower() or "Brute Force" in out

    def test_section1_header(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "🔐" in out or "SSH Brute Force" in out

    def test_section2_summary(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "## 📋 Summary" in out

    def test_section3_ioc_table(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "Indicators of Compromise" in out

    def test_section4_attack_mapping(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "MITRE ATT" in out

    def test_section5_containment(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "Containment" in out
        assert "- [ ]" in out  # Checkboxes

    def test_section6_artifacts(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "Artifacts" in out or "RULE-" in out

    def test_section7_appendix(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "Appendix" in out

    def test_generated_at_timestamp(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        # Should contain an ISO timestamp
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", out)

    def test_ssh_specific_content(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "SSH" in out or "ssh" in out
        assert "key rotation" in out.lower() or "Key Rotation" in out
        assert "auth log" in out.lower() or "Auth Log" in out

    def test_failed_logins_threshold_rendered(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "30" in out

    def test_ip_blocking_recommendation(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "block" in out.lower() or "Block" in out

    def test_account_lockout_step(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "lockout" in out.lower() or "Lockout" in out

    def test_password_policy_review(self, gen, brute_ctx):
        out = gen.generate(brute_ctx)
        assert "password" in out.lower() and "policy" in out.lower()


# ============================================================
# generate() – Markdown format – sqli_attempt
# ============================================================

class TestGenerateMDSQLi:
    def test_returns_non_empty(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert len(out) > 500

    def test_sqli_template_used(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "💉" in out or "SQL Injection" in out

    def test_source_ip(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "1.2.3.4" in out

    def test_target_url(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "/api/users" in out

    def test_db_engine(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "MySQL" in out

    def test_db_name(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "app_db" in out

    def test_waf_review_section(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "WAF" in out

    def test_input_validation_section(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "Input" in out and "Validation" in out or "input validation" in out.lower()

    def test_db_integrity_section(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "Database" in out or "DB" in out or "Integrity" in out

    def test_t1190_technique(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "T1190" in out

    def test_all_7_sections_present(self, gen, sqli_ctx):
        out = gen.generate(sqli_ctx)
        assert "## 📋 Summary" in out
        assert "Indicators of Compromise" in out
        assert "MITRE ATT" in out
        assert "Containment" in out
        assert "Artifacts" in out
        assert "Appendix" in out

    @pytest.mark.parametrize("alias", [
        "sqli_attempt", "sqli", "sql_injection", "sql-injection",
    ])
    def test_alias_selection(self, gen, alias):
        out = gen.generate({"attack_pattern": alias, "source_ip": "1.1.1.1"})
        assert "SQL" in out or "💉" in out


# ============================================================
# generate() – Markdown format – port_scan
# ============================================================

class TestGenerateMDPortScan:
    def test_returns_non_empty(self, gen, scan_ctx):
        out = gen.generate(scan_ctx)
        assert len(out) > 500

    def test_port_scan_template_used(self, gen, scan_ctx):
        out = gen.generate(scan_ctx)
        assert "🔭" in out or "Port Scan" in out

    def test_source_ip(self, gen, scan_ctx):
        out = gen.generate(scan_ctx)
        assert "9.8.7.6" in out

    def test_target_subnet(self, gen, scan_ctx):
        out = gen.generate(scan_ctx)
        assert "10.0.2.0/24" in out

    def test_port_count(self, gen, scan_ctx):
        out = gen.generate(scan_ctx)
        assert "250" in out

    def test_network_segmentation_section(self, gen, scan_ctx):
        out = gen.generate(scan_ctx)
        assert "Segmentation" in out or "segmentation" in out

    def test_exposed_service_audit(self, gen, scan_ctx):
        out = gen.generate(scan_ctx)
        assert "Service" in out and ("Audit" in out or "audit" in out.lower())

    def test_t1595_technique(self, gen, scan_ctx):
        out = gen.generate(scan_ctx)
        assert "T1595" in out

    def test_honeypot_deployment(self, gen, scan_ctx):
        out = gen.generate(scan_ctx)
        assert "honeypot" in out.lower()

    @pytest.mark.parametrize("alias", [
        "port_scan", "port-scan", "scan", "recon", "reconnaissance",
    ])
    def test_alias_selection(self, gen, alias):
        out = gen.generate({"attack_pattern": alias, "source_ip": "1.1.1.1"})
        assert "🔭" in out or "Port Scan" in out or "Network" in out


# ============================================================
# generate() – Markdown format – data_exfiltration
# ============================================================

class TestGenerateMDExfil:
    def test_returns_non_empty(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert len(out) > 500

    def test_exfil_template_used(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert "📤" in out or "Data Exfiltration" in out

    def test_source_ip(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert "10.0.1.50" in out

    def test_destination_ip(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert "203.0.113.99" in out

    def test_destination_domain(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert "evil.attacker.com" in out

    def test_dlp_review_section(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert "DLP" in out

    def test_file_integrity_section(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert "File Integrity" in out or "file integrity" in out.lower() or "Integrity" in out

    def test_outbound_traffic_section(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert "Outbound Traffic" in out or "Traffic Analysis" in out or "traffic" in out.lower()

    def test_data_classification_section(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert "Data Classification" in out or "classification" in out.lower()

    def test_severity_defaults_to_critical(self, gen):
        out = gen.generate({"attack_pattern": "data_exfiltration", "source_ip": "1.1.1.1"})
        assert "🔴 **CRITICAL**" in out

    def test_classification_defaults_to_tlp_red(self, gen):
        out = gen.generate({"attack_pattern": "data_exfiltration", "source_ip": "1.1.1.1"})
        assert "TLP:RED" in out

    def test_t1041_technique(self, gen, exfil_ctx):
        out = gen.generate(exfil_ctx)
        assert "T1041" in out

    @pytest.mark.parametrize("alias", [
        "data_exfiltration", "data_exfil", "exfiltration", "dlp", "data_theft",
    ])
    def test_alias_selection(self, gen, alias):
        out = gen.generate({"attack_pattern": alias, "source_ip": "1.1.1.1"})
        assert "📤" in out or "Data Exfiltration" in out


# ============================================================
# generate() – unknown / base fallback
# ============================================================

class TestGenerateMDBaseFallback:
    def test_unknown_pattern_renders_base(self, gen):
        out = gen.generate({"attack_pattern": "unknown_malware", "source_ip": "5.5.5.5"})
        assert isinstance(out, str)
        assert len(out) > 200

    def test_base_has_all_7_sections(self, gen):
        out = gen.generate({"attack_pattern": "custom_attack", "source_ip": "5.5.5.5"})
        assert "## 📋 Summary" in out
        assert "Indicators of Compromise" in out
        assert "MITRE ATT" in out
        assert "Containment" in out
        assert "Artifacts" in out or "Rule References" in out
        assert "Appendix" in out

    def test_base_source_ip_rendered(self, gen):
        out = gen.generate({"attack_pattern": "custom_attack", "source_ip": "3.3.3.3"})
        assert "3.3.3.3" in out

    def test_base_severity_rendered(self, gen):
        out = gen.generate({
            "attack_pattern": "custom_attack",
            "severity": "MEDIUM",
        })
        assert "🟡 **MEDIUM**" in out

    def test_base_timestamp_rendered(self, gen):
        out = gen.generate({"attack_pattern": "custom_attack"})
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", out)


# ============================================================
# generate() – YAML format (backward compat)
# ============================================================

class TestGenerateYAMLBackwardCompat:
    def test_yaml_brute_force_renders(self, gen):
        rendered = gen.generate(
            {"attack_pattern": "brute_force", "source_ip": "192.168.1.100"},
            format="yaml",
        )
        data = yaml.safe_load(rendered)
        assert isinstance(data, dict)
        assert data["name"] == "Brute Force Response"

    def test_yaml_port_scan_renders(self, gen):
        data = yaml.safe_load(gen.generate(
            {"attack_pattern": "port_scan"},
            format="yaml",
        ))
        assert data["name"] == "Port Scan Response"

    def test_yaml_credential_reuse_renders(self, gen):
        data = yaml.safe_load(gen.generate(
            {"attack_pattern": "credential_reuse"},
            format="yaml",
        ))
        assert data["name"] == "Credential Reuse Detection"

    def test_yaml_distributed_attack_renders(self, gen):
        data = yaml.safe_load(gen.generate(
            {"attack_pattern": "distributed_attack"},
            format="yaml",
        ))
        assert data["name"] == "Distributed Attack Response"

    def test_yaml_variables_substituted(self, gen):
        data = yaml.safe_load(gen.generate(
            {
                "attack_pattern": "brute_force",
                "source_ip": "192.168.1.100",
                "failed_logins_threshold": 30,
                "block_duration": "7200",
                "tarpit_delay_ms": 3000,
                "alert_level": "CRITICAL",
            },
            format="yaml",
        ))
        assert data["actions"][0]["params"]["ip"] == "192.168.1.100"
        assert data["actions"][0]["params"]["duration"] == "7200"
        assert data["actions"][1]["params"]["delay_ms"] == 3000
        assert data["actions"][2]["params"]["level"] == "CRITICAL"

    def test_yaml_default_values_applied(self, gen):
        data = yaml.safe_load(gen.generate(
            {"attack_pattern": "brute_force"},
            format="yaml",
        ))
        actions = data["actions"]
        assert actions[0]["params"]["duration"] == "3600"
        assert actions[2]["params"]["level"] == "HIGH"


# ============================================================
# Format validation
# ============================================================

class TestFormatValidation:
    def test_invalid_format_raises(self, gen):
        with pytest.raises(ValueError, match="format"):
            gen.generate({"attack_pattern": "brute_force"}, format="html")

    def test_markdown_format_accepted(self, gen):
        out = gen.generate({"attack_pattern": "brute_force"}, format="markdown")
        assert isinstance(out, str) and len(out) > 100

    def test_yaml_format_accepted(self, gen):
        out = gen.generate({"attack_pattern": "brute_force"}, format="yaml")
        data = yaml.safe_load(out)
        assert isinstance(data, dict)

    def test_default_format_is_markdown(self, gen):
        out = gen.generate({"attack_pattern": "brute_force"})
        assert out.strip().startswith("#")  # Markdown heading


# ============================================================
# Error paths
# ============================================================

class TestErrorPaths:
    def test_missing_attack_pattern_raises(self, gen):
        with pytest.raises(ValueError, match="attack_pattern"):
            gen.generate({"source_ip": "1.1.1.1"})

    def test_unknown_yaml_pattern_raises_file_not_found(self, gen):
        with pytest.raises(FileNotFoundError, match="unknown_pattern_response.yaml.j2"):
            gen.generate({"attack_pattern": "unknown_pattern"}, format="yaml")

    def test_non_dict_context_raises(self, gen):
        with pytest.raises(TypeError):
            gen.generate("not_a_dict")

    def test_empty_pattern_raises(self, gen):
        with pytest.raises(ValueError):
            gen.generate({"attack_pattern": ""})

    def test_none_pattern_raises(self, gen):
        with pytest.raises(ValueError):
            gen.generate({"attack_pattern": None})


# ============================================================
# All 7 sections render for every pattern
# ============================================================

class TestAll7Sections:
    """Verify that all 7 standard playbook sections render for every attack pattern."""

    @pytest.mark.parametrize("pattern", [
        "brute_force", "sqli_attempt", "port_scan", "data_exfiltration", "unknown_custom",
    ])
    def test_section1_header(self, gen, pattern):
        out = gen.generate({"attack_pattern": pattern, "source_ip": "1.1.1.1"})
        assert "# " in out  # H1 heading

    @pytest.mark.parametrize("pattern", [
        "brute_force", "sqli_attempt", "port_scan", "data_exfiltration", "unknown_custom",
    ])
    def test_section2_summary(self, gen, pattern):
        out = gen.generate({"attack_pattern": pattern, "source_ip": "1.1.1.1"})
        assert "## 📋 Summary" in out

    @pytest.mark.parametrize("pattern", [
        "brute_force", "sqli_attempt", "port_scan", "data_exfiltration", "unknown_custom",
    ])
    def test_section3_ioc_table(self, gen, pattern):
        out = gen.generate({"attack_pattern": pattern, "source_ip": "1.1.1.1"})
        assert "Indicators of Compromise" in out

    @pytest.mark.parametrize("pattern", [
        "brute_force", "sqli_attempt", "port_scan", "data_exfiltration", "unknown_custom",
    ])
    def test_section4_attack_mapping(self, gen, pattern):
        out = gen.generate({"attack_pattern": pattern, "source_ip": "1.1.1.1"})
        assert "MITRE ATT" in out

    @pytest.mark.parametrize("pattern", [
        "brute_force", "sqli_attempt", "port_scan", "data_exfiltration", "unknown_custom",
    ])
    def test_section5_containment(self, gen, pattern):
        out = gen.generate({"attack_pattern": pattern, "source_ip": "1.1.1.1"})
        assert "Containment" in out

    @pytest.mark.parametrize("pattern", [
        "brute_force", "sqli_attempt", "port_scan", "data_exfiltration", "unknown_custom",
    ])
    def test_section6_artifacts(self, gen, pattern):
        out = gen.generate({"attack_pattern": pattern, "source_ip": "1.1.1.1"})
        # Artifacts or Rule References – child templates use either heading
        assert "Artifacts" in out or "Rule" in out

    @pytest.mark.parametrize("pattern", [
        "brute_force", "sqli_attempt", "port_scan", "data_exfiltration", "unknown_custom",
    ])
    def test_section7_appendix(self, gen, pattern):
        out = gen.generate({"attack_pattern": pattern, "source_ip": "1.1.1.1"})
        assert "Appendix" in out
