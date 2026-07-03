"""
tests/test_playbook_generator.py
---------------------------------
Comprehensive tests for PlaybookGenerator covering:

  1. Template selection — all 4 attack patterns + base fallback
  2. IOC table rendering — all columns, custom IOC objects, threat intel labels
  3. ATT&CK mapping section — technique IDs, names, tactics, MITRE links
  4. Minimal/empty input — graceful handling with safe defaults
  5. Maximum input — no truncation, no overflow

These tests run directly against the backend/sentinel/ production package
(resolved via tests/conftest.py which adds backend/ to sys.path).
"""

import os
import re
import sys
import pytest

# ---------------------------------------------------------------------------
# Path bootstrap (belt-and-suspenders in case conftest is not picked up)
# ---------------------------------------------------------------------------
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "backend")
for _p in (_ROOT, _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from sentinel.playbook_generator import PlaybookGenerator


# ===========================================================================
# Shared fixture
# ===========================================================================

@pytest.fixture(scope="module")
def gen():
    return PlaybookGenerator()


# ===========================================================================
# 1. TEMPLATE SELECTION
#    Verify each attack pattern keyword routes to the correct .md.j2 template
# ===========================================================================

class TestTemplateSelection:
    """
    Requirement: _select_template(pattern, format='markdown') must return the
    correct filename for every supported keyword.
    """

    # ── Brute-force variants ────────────────────────────────────────────────
    @pytest.mark.parametrize("pattern", [
        "brute_force",
        "brute-force",
        "BRUTE_FORCE",
        "failed_login",
        "Failed_Login",
        "ssh_brute",
        "SSH_BRUTE_FORCE_DISTRIBUTED",
    ])
    def test_brute_force_selects_correct_template(self, gen, pattern):
        """brute_force and all aliases → brute_force.md.j2"""
        result = gen._select_template(pattern, format="markdown")
        assert result == "brute_force.md.j2", (
            f"Pattern '{pattern}' should select brute_force.md.j2, got '{result}'"
        )

    # ── SQL injection variants ──────────────────────────────────────────────
    @pytest.mark.parametrize("pattern", [
        "sqli_attempt",
        "sqli",
        "SQLI",
        "sql_injection",
        "sql-injection",
        "SQL_INJECTION",
    ])
    def test_sqli_selects_correct_template(self, gen, pattern):
        """sqli and all aliases → sqli_attempt.md.j2"""
        result = gen._select_template(pattern, format="markdown")
        assert result == "sqli_attempt.md.j2", (
            f"Pattern '{pattern}' should select sqli_attempt.md.j2, got '{result}'"
        )

    # ── Port scan / recon variants ──────────────────────────────────────────
    @pytest.mark.parametrize("pattern", [
        "port_scan",
        "port-scan",
        "PORT_SCAN",
        "scan",
        "SCAN",
        "recon",
        "RECON",
        "reconnaissance",
        "RECONNAISSANCE",
    ])
    def test_port_scan_selects_correct_template(self, gen, pattern):
        """port_scan and all aliases → port_scan.md.j2"""
        result = gen._select_template(pattern, format="markdown")
        assert result == "port_scan.md.j2", (
            f"Pattern '{pattern}' should select port_scan.md.j2, got '{result}'"
        )

    # ── Data exfiltration variants ──────────────────────────────────────────
    @pytest.mark.parametrize("pattern", [
        "data_exfiltration",
        "data_exfil",
        "DATA_EXFILTRATION",
        "exfiltration",
        "dlp",
        "DLP",
        "data_theft",
        "DATA_THEFT",
    ])
    def test_data_exfil_selects_correct_template(self, gen, pattern):
        """data_exfiltration and all aliases → data_exfiltration.md.j2"""
        result = gen._select_template(pattern, format="markdown")
        assert result == "data_exfiltration.md.j2", (
            f"Pattern '{pattern}' should select data_exfiltration.md.j2, got '{result}'"
        )

    # ── Unknown pattern fallback ────────────────────────────────────────────
    @pytest.mark.parametrize("pattern", [
        "unknown_pattern",
        "custom_attack",
        "zero_day",
        "ransomware",
        "malware",
        "lateral_movement",
        "supply_chain",
        "",  # empty string also falls back
    ])
    def test_unknown_pattern_falls_back_to_base(self, gen, pattern):
        """Anything unrecognised → base_playbook.md.j2 fallback"""
        # Empty string raises ValueError before template selection,
        # so skip that specific case here (covered in error-path tests).
        if pattern == "":
            pytest.skip("Empty pattern raises ValueError — tested in TestErrorPaths")
        result = gen._select_template(pattern, format="markdown")
        assert result == "base_playbook.md.j2", (
            f"Unknown pattern '{pattern}' should fall back to base_playbook.md.j2, got '{result}'"
        )

    def test_selection_is_case_insensitive(self, gen):
        """Pattern matching must be case-insensitive."""
        assert gen._select_template("BRUTE_FORCE", format="markdown") == "brute_force.md.j2"
        assert gen._select_template("Sqli_Attempt", format="markdown") == "sqli_attempt.md.j2"
        assert gen._select_template("Port_Scan", format="markdown") == "port_scan.md.j2"
        assert gen._select_template("Data_Exfiltration", format="markdown") == "data_exfiltration.md.j2"

    def test_selection_returns_string(self, gen):
        """Return value must always be a non-empty string."""
        for pattern in ["brute_force", "sqli_attempt", "port_scan", "data_exfiltration", "unknown"]:
            result = gen._select_template(pattern, format="markdown")
            assert isinstance(result, str) and len(result) > 0

    def test_all_selected_templates_exist_on_disk(self, gen):
        """Every template returned by _select_template must exist as a real file."""
        templates_dir = gen.templates_dir
        for pattern in ["brute_force", "sqli_attempt", "port_scan", "data_exfiltration", "unknown"]:
            name = gen._select_template(pattern, format="markdown")
            path = os.path.join(templates_dir, name)
            assert os.path.isfile(path), f"Template file missing: {path}"


# ===========================================================================
# 2. IOC TABLE RENDERING
#    Verify the IOC table section renders all columns from the context correctly
# ===========================================================================

class TestIOCTableRendering:
    """
    Each IOC dict must produce a properly-formatted Markdown table row with:
      IP | Ports | Protocol | Hit Count | Threat Intel | First Seen | Last Seen
    """

    @pytest.fixture
    def single_ioc_ctx(self):
        return {
            "attack_pattern": "brute_force",
            "source_ip": "10.0.0.1",
            "iocs": [
                {
                    "ip": "10.0.0.1",
                    "ports": "22",
                    "protocol": "TCP",
                    "hit_count": 999,
                    "threat_intel": "🔴 Known Botnet (AbuseIPDB 100%)",
                    "first_seen": "2026-06-24T08:00:00Z",
                    "last_seen":  "2026-06-24T12:00:00Z",
                }
            ],
        }

    @pytest.fixture
    def multi_ioc_ctx(self):
        return {
            "attack_pattern": "sqli_attempt",
            "source_ip": "5.5.5.5",
            "iocs": [
                {
                    "ip": "5.5.5.5",
                    "ports": "443",
                    "protocol": "TCP",
                    "hit_count": 120,
                    "threat_intel": "🔴 OTX Malicious",
                    "first_seen": "2026-06-24T10:00:00Z",
                    "last_seen":  "2026-06-24T10:30:00Z",
                },
                {
                    "ip": "6.6.6.6",
                    "ports": "80, 8080",
                    "protocol": "TCP",
                    "hit_count": 45,
                    "threat_intel": "🟠 Shodan Scanner",
                    "first_seen": "2026-06-24T10:05:00Z",
                    "last_seen":  "2026-06-24T10:28:00Z",
                },
                {
                    "ip": "7.7.7.7",
                    "ports": "443",
                    "protocol": "TCP",
                    "hit_count": 12,
                    "threat_intel": "🟡 Low Confidence",
                    "first_seen": "2026-06-24T10:10:00Z",
                    "last_seen":  "2026-06-24T10:25:00Z",
                },
            ],
        }

    def test_ioc_section_heading_present(self, gen, single_ioc_ctx):
        out = gen.generate(single_ioc_ctx)
        assert "Indicators of Compromise" in out

    def test_ioc_table_has_markdown_table(self, gen, single_ioc_ctx):
        out = gen.generate(single_ioc_ctx)
        # A Markdown table must have at least one row with pipe characters
        assert re.search(r"^\|.+\|.+\|", out, re.MULTILINE), \
            "IOC section must contain a Markdown table"

    def test_ioc_ip_rendered(self, gen, single_ioc_ctx):
        out = gen.generate(single_ioc_ctx)
        assert "10.0.0.1" in out

    def test_ioc_port_rendered(self, gen, single_ioc_ctx):
        out = gen.generate(single_ioc_ctx)
        assert "22" in out

    def test_ioc_protocol_rendered(self, gen, single_ioc_ctx):
        out = gen.generate(single_ioc_ctx)
        assert "TCP" in out

    def test_ioc_hit_count_rendered(self, gen, single_ioc_ctx):
        out = gen.generate(single_ioc_ctx)
        assert "999" in out

    def test_ioc_threat_intel_label_rendered(self, gen, single_ioc_ctx):
        out = gen.generate(single_ioc_ctx)
        assert "AbuseIPDB" in out or "Known Botnet" in out

    def test_ioc_first_seen_rendered(self, gen, single_ioc_ctx):
        out = gen.generate(single_ioc_ctx)
        assert "2026-06-24" in out

    def test_ioc_last_seen_rendered(self, gen, single_ioc_ctx):
        out = gen.generate(single_ioc_ctx)
        assert "12:00" in out or "2026-06-24T12:00:00Z" in out

    def test_multi_ioc_all_ips_rendered(self, gen, multi_ioc_ctx):
        out = gen.generate(multi_ioc_ctx)
        assert "5.5.5.5" in out
        assert "6.6.6.6" in out
        assert "7.7.7.7" in out

    def test_multi_ioc_all_hit_counts_rendered(self, gen, multi_ioc_ctx):
        out = gen.generate(multi_ioc_ctx)
        assert "120" in out
        assert "45" in out
        assert "12" in out

    def test_multi_ioc_threat_intel_severity_icons(self, gen, multi_ioc_ctx):
        out = gen.generate(multi_ioc_ctx)
        assert "🔴" in out
        assert "🟠" in out
        assert "🟡" in out

    def test_no_none_values_in_ioc_table(self, gen):
        """IOC table must never render raw 'None' in any cell."""
        out = gen.generate({
            "attack_pattern": "brute_force",
            "source_ip": "1.1.1.1",
            "iocs": [{"ip": "1.1.1.1"}],  # minimal IOC — all other fields missing
        })
        assert "| None |" not in out
        assert "None" not in out.split("Indicators of Compromise")[1].split("##")[0]

    def test_ioc_auto_built_from_source_ip_when_no_ioc_list(self, gen):
        """If 'iocs' not provided, the generator must auto-build from source_ip."""
        out = gen.generate({
            "attack_pattern": "port_scan",
            "source_ip": "192.168.99.1",
        })
        assert "192.168.99.1" in out

    def test_ioc_table_has_header_separator_row(self, gen, single_ioc_ctx):
        """Markdown table requires a separator row (|---|---|)."""
        out = gen.generate(single_ioc_ctx)
        assert re.search(r"^\|[-:| ]+\|$", out, re.MULTILINE), \
            "IOC table must have a Markdown header separator row"

    @pytest.mark.parametrize("pattern", [
        "brute_force", "sqli_attempt", "port_scan", "data_exfiltration",
    ])
    def test_ioc_table_present_for_all_patterns(self, gen, pattern):
        """IOC table must appear for every attack pattern."""
        out = gen.generate({
            "attack_pattern": pattern,
            "source_ip": "1.2.3.4",
        })
        assert "Indicators of Compromise" in out
        assert re.search(r"^\|.+\|.+\|", out, re.MULTILINE)


# ===========================================================================
# 3. ATT&CK MAPPING SECTION
#    Verify MITRE technique data is correctly populated for each pattern
# ===========================================================================

class TestATTACKMappingSection:
    """
    The ATT&CK section must render:
      - A heading containing 'MITRE ATT&CK'
      - A table with Technique ID, Name, Tactic columns
      - Correct technique IDs per attack pattern
      - Clickable attack.mitre.org hyperlinks
    """

    def test_attack_section_heading_present(self, gen):
        out = gen.generate({"attack_pattern": "brute_force"})
        assert "MITRE ATT" in out, "ATT&CK section heading must be present"

    def test_attack_table_columns(self, gen):
        out = gen.generate({"attack_pattern": "brute_force"})
        assert "Technique" in out
        assert "Tactic" in out

    def test_mitre_link_present(self, gen):
        out = gen.generate({"attack_pattern": "brute_force"})
        assert "attack.mitre.org" in out, "MITRE ATT&CK hyperlinks must be present"

    # ── Brute-force techniques ──────────────────────────────────────────────
    def test_brute_force_t1110_present(self, gen):
        """T1110 (Brute Force) must appear for brute_force pattern."""
        out = gen.generate({"attack_pattern": "brute_force", "source_ip": "1.1.1.1"})
        assert "T1110" in out

    def test_brute_force_t1110_name(self, gen):
        out = gen.generate({"attack_pattern": "brute_force", "source_ip": "1.1.1.1"})
        assert "Brute Force" in out

    def test_brute_force_t1078_valid_accounts(self, gen):
        """T1078 (Valid Accounts) must appear as secondary technique."""
        out = gen.generate({"attack_pattern": "brute_force", "source_ip": "1.1.1.1"})
        assert "T1078" in out

    def test_brute_force_t1021_remote_services(self, gen):
        """T1021 (Remote Services) must appear for SSH brute force."""
        out = gen.generate({"attack_pattern": "brute_force", "source_ip": "1.1.1.1"})
        assert "T1021" in out

    # ── SQL injection techniques ────────────────────────────────────────────
    def test_sqli_t1190_present(self, gen):
        """T1190 (Exploit Public-Facing Application) must appear for sqli."""
        out = gen.generate({"attack_pattern": "sqli_attempt", "source_ip": "2.2.2.2"})
        assert "T1190" in out

    def test_sqli_t1190_name(self, gen):
        out = gen.generate({"attack_pattern": "sqli_attempt", "source_ip": "2.2.2.2"})
        assert "Public-Facing" in out or "Exploit" in out

    def test_sqli_tactic_initial_access(self, gen):
        out = gen.generate({"attack_pattern": "sqli_attempt", "source_ip": "2.2.2.2"})
        assert "Initial Access" in out

    # ── Port scan techniques ────────────────────────────────────────────────
    def test_port_scan_t1595_present(self, gen):
        """T1595 (Active Scanning) must appear for port_scan."""
        out = gen.generate({"attack_pattern": "port_scan", "source_ip": "3.3.3.3"})
        assert "T1595" in out

    def test_port_scan_t1046_present(self, gen):
        """T1046 (Network Service Discovery) must appear for port_scan."""
        out = gen.generate({"attack_pattern": "port_scan", "source_ip": "3.3.3.3"})
        assert "T1046" in out

    def test_port_scan_tactic_reconnaissance(self, gen):
        out = gen.generate({"attack_pattern": "port_scan", "source_ip": "3.3.3.3"})
        assert "Reconnaissance" in out or "Discovery" in out

    # ── Data exfiltration techniques ────────────────────────────────────────
    def test_exfil_t1041_present(self, gen):
        """T1041 (Exfiltration Over C2 Channel) must appear for data_exfiltration."""
        out = gen.generate({"attack_pattern": "data_exfiltration", "source_ip": "4.4.4.4"})
        assert "T1041" in out

    def test_exfil_t1048_present(self, gen):
        """T1048 (Exfiltration Over Alternative Protocol) must appear."""
        out = gen.generate({"attack_pattern": "data_exfiltration", "source_ip": "4.4.4.4"})
        assert "T1048" in out

    def test_exfil_tactic_exfiltration(self, gen):
        out = gen.generate({"attack_pattern": "data_exfiltration", "source_ip": "4.4.4.4"})
        assert "Exfiltration" in out

    # ── Base fallback techniques ────────────────────────────────────────────
    def test_base_fallback_has_at_least_one_technique(self, gen):
        """Unknown patterns use base_playbook.md.j2 else block.

        When no attack_techniques list is supplied, the template renders a
        T???? placeholder row; the MITRE ATT&CK heading is always present.
        """
        out = gen.generate({"attack_pattern": "unknown_threat"})
        # Heading must always appear
        assert "MITRE ATT" in out, "ATT&CK heading must be present in base fallback"
        # Else block renders either a real T#### or a T???? placeholder
        has_real_id = bool(re.search(r"T\d{4}", out))
        has_placeholder = "T????" in out
        assert has_real_id or has_placeholder, (
            "Base fallback must render a real technique ID (T####) or placeholder (T????)"
        )
        assert "attack.mitre.org" in out

    # ── Cross-pattern ───────────────────────────────────────────────────────
    @pytest.mark.parametrize("pattern,expected_technique", [
        ("brute_force",       "T1110"),
        ("sqli_attempt",      "T1190"),
        ("port_scan",         "T1595"),
        ("data_exfiltration", "T1041"),
    ])
    def test_primary_technique_per_pattern(self, gen, pattern, expected_technique):
        out = gen.generate({"attack_pattern": pattern, "source_ip": "1.1.1.1"})
        assert expected_technique in out, \
            f"Expected {expected_technique} in ATT&CK section for {pattern}"

    def test_caller_provided_techniques_stored_in_context(self, gen):
        """attack_techniques supplied by the caller must be stored in the
        enriched context (not overridden by the generator).  The brute_force
        template has its own hardcoded ATT&CK table, so custom technique IDs
        won't appear inline — but the enrichment must honour caller data.
        Verify via _build_enriched_context directly.
        """
        custom_techniques = [
            {
                "id": "T9999",
                "name": "Custom Technique",
                "tactic": "Custom Tactic",
                "description": "A test technique",
            }
        ]
        ctx = gen._build_enriched_context(
            {"attack_pattern": "brute_force", "attack_techniques": custom_techniques},
            "brute_force",
        )
        # Caller-supplied techniques must NOT be overridden by defaults
        assert ctx["attack_techniques"] == custom_techniques, \
            "_build_enriched_context must preserve caller-supplied attack_techniques"
        assert ctx["attack_techniques"][0]["id"] == "T9999"
        assert ctx["attack_techniques"][0]["name"] == "Custom Technique"


# ===========================================================================
# 4. MINIMAL / EMPTY INPUT — graceful handling
# ===========================================================================

class TestMinimalInput:
    """
    Generator must handle minimal context gracefully:
      - Only attack_pattern key supplied
      - Missing source_ip → safe default
      - Missing severity → default HIGH
      - Missing iocs → auto-built from source_ip or empty list
      - Missing timestamps → auto-generated
    """

    def test_only_attack_pattern_key_brute_force(self, gen):
        """Minimum possible input: only attack_pattern."""
        out = gen.generate({"attack_pattern": "brute_force"})
        assert isinstance(out, str) and len(out) > 200

    def test_only_attack_pattern_key_sqli(self, gen):
        out = gen.generate({"attack_pattern": "sqli_attempt"})
        assert isinstance(out, str) and len(out) > 200

    def test_only_attack_pattern_key_port_scan(self, gen):
        out = gen.generate({"attack_pattern": "port_scan"})
        assert isinstance(out, str) and len(out) > 200

    def test_only_attack_pattern_key_exfil(self, gen):
        out = gen.generate({"attack_pattern": "data_exfiltration"})
        assert isinstance(out, str) and len(out) > 200

    def test_only_attack_pattern_key_unknown(self, gen):
        out = gen.generate({"attack_pattern": "unknown_threat"})
        assert isinstance(out, str) and len(out) > 200

    def test_missing_source_ip_no_crash(self, gen):
        """No source_ip should not crash — N/A or empty placeholder expected."""
        out = gen.generate({"attack_pattern": "brute_force"})
        # Should render without exception and produce valid Markdown
        assert "# " in out

    def test_missing_severity_defaults_to_high(self, gen):
        out = gen.generate({"attack_pattern": "brute_force"})
        assert "HIGH" in out or "CRITICAL" in out

    def test_missing_iocs_no_crash(self, gen):
        """Missing iocs list should not crash; auto-building from source_ip."""
        out = gen.generate({"attack_pattern": "port_scan"})
        assert "Indicators of Compromise" in out

    def test_generated_at_auto_populated(self, gen):
        """generated_at must be auto-set to current UTC when not provided."""
        out = gen.generate({"attack_pattern": "brute_force"})
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", out), \
            "generated_at timestamp must be auto-populated"

    def test_no_raw_jinja_tags_in_minimal_output(self, gen):
        """No unrendered {{ }} or {% %} should appear in output."""
        out = gen.generate({"attack_pattern": "brute_force"})
        assert "{%" not in out
        assert "{{" not in out

    def test_no_undefined_in_minimal_output(self, gen):
        """Jinja2 Undefined must not leak into output."""
        for pattern in ["brute_force", "sqli_attempt", "port_scan", "data_exfiltration"]:
            out = gen.generate({"attack_pattern": pattern})
            assert "Undefined" not in out, \
                f"Jinja2 Undefined found in output for pattern '{pattern}'"

    def test_all_7_sections_present_with_minimal_input(self, gen):
        """All 7 playbook sections must render even with minimal input."""
        out = gen.generate({"attack_pattern": "brute_force"})
        assert "## 📋 Summary" in out
        assert "Indicators of Compromise" in out
        assert "MITRE ATT" in out
        assert "Containment" in out
        assert "Artifacts" in out or "RULE-" in out
        assert "## 📎 Appendix" in out

    def test_empty_ioc_list_no_crash(self, gen):
        """Explicitly passing an empty iocs list must not crash."""
        out = gen.generate({
            "attack_pattern": "port_scan",
            "source_ip": "1.1.1.1",
            "iocs": [],
        })
        assert isinstance(out, str) and len(out) > 100

    def test_extra_unknown_keys_ignored(self, gen):
        """Extra context keys must be silently passed through without error."""
        out = gen.generate({
            "attack_pattern": "brute_force",
            "unknown_key_xyz": "should be ignored",
            "another_random_field": 99999,
        })
        assert isinstance(out, str) and len(out) > 100


# ===========================================================================
# 5. MAXIMUM INPUT — no truncation or overflow
# ===========================================================================

class TestMaximumInput:
    """
    Generator must handle large, data-rich context without:
      - Truncating text
      - Raising exceptions
      - Producing garbled Markdown
    """

    @pytest.fixture
    def max_brute_force_ctx(self):
        """Large brute-force context with 20 IOCs, 5 techniques, large lists."""
        return {
            "attack_pattern": "brute_force",
            "title": "SSH Brute Force – Large Scale Attack " + ("X" * 200),
            "severity": "CRITICAL",
            "source_ip": "185.220.101.42",
            "target_ip": "10.0.2.15",
            "ssh_port": 2222,
            "failed_logins_threshold": 99999,
            "timeframe": "72 hours",
            "timeframe_seconds": "259200s",
            "block_duration": "604800",
            "tarpit_delay_ms": 30000,
            "alert_level": "CRITICAL",
            "targeted_usernames": [f"user_{i}" for i in range(50)],
            "key_rotation_hosts": [f"10.0.{i}.1" for i in range(20)],
            "lockout_policy_threshold": 1,
            "min_password_length": 32,
            "geo_block_country": "RU,CN,KP,IR,BY",
            "audit_period_hours": 720,
            "iocs": [
                {
                    "ip": f"185.220.{i}.{i+1}",
                    "ports": "2222, 22",
                    "protocol": "TCP",
                    "hit_count": (i + 1) * 1000,
                    "threat_intel": f"🔴 Tor Exit Node #{i} (AbuseIPDB 100%)",
                    "first_seen": f"2026-06-{i+1:02d}T00:00:00Z",
                    "last_seen": f"2026-06-{i+1:02d}T23:59:59Z",
                }
                for i in range(20)
            ],
            "attack_techniques": [
                {
                    "id": f"T110{i}",
                    "name": f"Technique {i}",
                    "tactic": "Credential Access",
                    "description": "A" * 500,
                }
                for i in range(5)
            ],
            "containment_steps": [f"Step {i}: " + "Do something " * 20 for i in range(30)],
        }

    @pytest.fixture
    def max_exfil_ctx(self):
        """Large data-exfiltration context with 50 affected files."""
        return {
            "attack_pattern": "data_exfiltration",
            "severity": "CRITICAL",
            "source_ip": "10.0.1.50",
            "destination_ip": "198.51.100.42",
            "destination_domain": "c2.attacker.example.com",
            "exfil_bytes": 107374182400,  # 100 GB
            "exfil_bytes_hr": "100 GB",
            "data_classification": "SECRET",
            "breach_notif_required": True,
            "insider_threat": True,
            "affected_files": [f"/data/sensitive/file_{i}.enc" for i in range(50)],
            "affected_systems": [f"10.0.{i}.{i}" for i in range(20)],
            "affected_data_types": ["PII", "PCI", "PHI", "IP", "source_code", "credentials"],
            "iocs": [
                {
                    "ip": f"198.51.{i}.{i}",
                    "ports": "443, 53",
                    "protocol": "TCP/UDP",
                    "hit_count": i * 100,
                    "threat_intel": f"🔴 C2 Server #{i}",
                    "first_seen": "2026-06-01T00:00:00Z",
                    "last_seen": "2026-06-24T23:59:59Z",
                }
                for i in range(10)
            ],
        }

    def test_max_input_renders_without_exception(self, gen, max_brute_force_ctx):
        out = gen.generate(max_brute_force_ctx)
        assert isinstance(out, str)

    def test_max_input_output_not_empty(self, gen, max_brute_force_ctx):
        out = gen.generate(max_brute_force_ctx)
        assert len(out) > 1000

    def test_max_input_all_20_ioc_ips_rendered(self, gen, max_brute_force_ctx):
        out = gen.generate(max_brute_force_ctx)
        for i in range(20):
            ip = f"185.220.{i}.{i+1}"
            assert ip in out, f"IOC IP {ip} missing from output"

    def test_max_input_hardcoded_techniques_still_render(self, gen, max_brute_force_ctx):
        """brute_force.md.j2 has hardcoded ATT&CK rows — even with custom
        attack_techniques in context, the template's own rows must still render.
        """
        out = gen.generate(max_brute_force_ctx)
        # These are hardcoded in brute_force.md.j2
        assert "T1110" in out, "T1110 (Brute Force) must be in brute_force template"
        assert "T1078" in out, "T1078 (Valid Accounts) must be in brute_force template"
        # Also verify the enriched context carries the custom techniques
        ctx = gen._build_enriched_context(max_brute_force_ctx, "brute_force")
        assert ctx["attack_techniques"] == max_brute_force_ctx["attack_techniques"], \
            "Caller attack_techniques must be preserved in enriched context"

    def test_max_input_high_hit_count_rendered(self, gen, max_brute_force_ctx):
        out = gen.generate(max_brute_force_ctx)
        assert "20000" in out  # 20th IOC: (19+1)*1000 = 20000

    def test_max_input_failed_logins_99999_rendered(self, gen, max_brute_force_ctx):
        out = gen.generate(max_brute_force_ctx)
        assert "99999" in out

    def test_max_input_no_raw_jinja_tags(self, gen, max_brute_force_ctx):
        out = gen.generate(max_brute_force_ctx)
        assert "{%" not in out
        assert "{{" not in out

    def test_max_input_no_undefined(self, gen, max_brute_force_ctx):
        out = gen.generate(max_brute_force_ctx)
        assert "Undefined" not in out

    def test_max_input_no_none_in_table_cells(self, gen, max_brute_force_ctx):
        out = gen.generate(max_brute_force_ctx)
        assert "| None |" not in out

    def test_max_exfil_renders_without_exception(self, gen, max_exfil_ctx):
        out = gen.generate(max_exfil_ctx)
        assert isinstance(out, str)

    def test_max_exfil_50_files_all_rendered(self, gen, max_exfil_ctx):
        out = gen.generate(max_exfil_ctx)
        # First and last files must appear
        assert "/data/sensitive/file_0.enc" in out
        assert "/data/sensitive/file_49.enc" in out

    def test_max_exfil_10_ioc_ips_rendered(self, gen, max_exfil_ctx):
        out = gen.generate(max_exfil_ctx)
        for i in range(10):
            ip = f"198.51.{i}.{i}"
            assert ip in out, f"IOC IP {ip} missing in exfil max output"

    def test_max_exfil_100gb_volume_rendered(self, gen, max_exfil_ctx):
        out = gen.generate(max_exfil_ctx)
        assert "100 GB" in out

    def test_max_input_valid_markdown_structure(self, gen, max_brute_force_ctx):
        """Even with large input, output must maintain valid Markdown structure."""
        out = gen.generate(max_brute_force_ctx)
        assert re.search(r"^# .+", out, re.MULTILINE), "Must have H1 heading"
        assert len(re.findall(r"^## .+", out, re.MULTILINE)) >= 5, "Must have ≥5 H2 headings"
        assert re.search(r"^\|.+\|.+\|", out, re.MULTILINE), "Must have Markdown tables"
        assert "- [ ]" in out, "Must have checkboxes"

    def test_caller_dict_not_mutated_max_input(self, gen, max_brute_force_ctx):
        """generate() must never mutate the caller's dict."""
        original_keys = set(max_brute_force_ctx.keys())
        gen.generate(max_brute_force_ctx)
        assert set(max_brute_force_ctx.keys()) == original_keys


# ===========================================================================
# 6. ERROR PATHS
# ===========================================================================

class TestErrorPaths:
    def test_missing_attack_pattern_raises_value_error(self, gen):
        with pytest.raises(ValueError, match="attack_pattern"):
            gen.generate({"source_ip": "1.1.1.1"})

    def test_empty_attack_pattern_raises_value_error(self, gen):
        with pytest.raises(ValueError):
            gen.generate({"attack_pattern": ""})

    def test_none_attack_pattern_raises_value_error(self, gen):
        with pytest.raises(ValueError):
            gen.generate({"attack_pattern": None})

    def test_non_dict_raises_type_error(self, gen):
        with pytest.raises(TypeError):
            gen.generate("brute_force")

    def test_list_raises_type_error(self, gen):
        with pytest.raises(TypeError):
            gen.generate(["attack_pattern", "brute_force"])

    def test_invalid_format_raises_value_error(self, gen):
        with pytest.raises(ValueError, match="format"):
            gen.generate({"attack_pattern": "brute_force"}, format="xml")

    def test_unknown_yaml_pattern_raises_file_not_found(self, gen):
        with pytest.raises(FileNotFoundError):
            gen.generate({"attack_pattern": "unknown_pattern"}, format="yaml")
