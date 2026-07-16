#!/usr/bin/env python3
"""
tests/test_llm_sqli_portscan_eval.py
--------------------------------------
Unit tests for the SQL Injection and Port Scanning LLM quality evaluation framework.
Validates prompt construction, markdown quality checks, factual accuracy detection,
security compliance mapping, and composite scoring logic.
"""

import os
import re
import sys
import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.llm_sqli_portscan_eval import (
    SQLI_TELEMETRY_CONTEXT,
    PORTSCAN_TELEMETRY_CONTEXT,
    REQUIRED_SECTIONS,
    build_sqli_prompt_v1_raw,
    build_sqli_prompt_v2_structured,
    build_sqli_prompt_v3_hardened,
    build_portscan_prompt_v1_raw,
    build_portscan_prompt_v2_structured,
    build_portscan_prompt_v3_hardened,
    check_factual_accuracy,
    check_markdown_structure,
    check_security_compliance,
    compute_quality_score,
)


# ─────────────────────────────────────────────────────────────────────
# 1. Prompt Construction Tests
# ─────────────────────────────────────────────────────────────────────

class TestPromptConstruction:
    """Verify prompt variants contain necessary telemetry context."""

    def test_sqli_v1_contains_telemetry(self):
        prompt = build_sqli_prompt_v1_raw()
        assert "CAMP-W17-SQLI-001" in prompt
        assert "203.0.113.101" in prompt
        assert "203.0.113.102" in prompt
        assert "8080" in prompt
        assert "320" in prompt
        assert "/api/v1/users/login" in prompt
        assert "UNION SELECT" in prompt

    def test_sqli_v2_has_fences_and_sections(self):
        prompt = build_sqli_prompt_v2_structured()
        assert "--- BEGIN TELEMETRY ---" in prompt
        assert "--- END TELEMETRY ---" in prompt
        assert "Do NOT fabricate" in prompt
        for section in REQUIRED_SECTIONS:
            assert f"## {section}" in prompt

    def test_sqli_v3_has_strict_rules(self):
        prompt = build_sqli_prompt_v3_hardened()
        assert "STRICT RULES" in prompt
        assert "No HTML" in prompt
        assert "Indicator | Type | Context" in prompt
        assert "alert tcp" in prompt

    def test_portscan_v1_contains_telemetry(self):
        prompt = build_portscan_prompt_v1_raw()
        assert "CAMP-W17-PORT-SCAN-001" in prompt
        assert "198.51.100.50" in prompt
        assert "SYN Scan" in prompt
        assert "1500" in prompt
        assert "85" in prompt

    def test_portscan_v2_has_fences_and_sections(self):
        prompt = build_portscan_prompt_v2_structured()
        assert "--- BEGIN TELEMETRY ---" in prompt
        assert "--- END TELEMETRY ---" in prompt
        assert "Do NOT fabricate" in prompt
        for section in REQUIRED_SECTIONS:
            assert f"## {section}" in prompt

    def test_portscan_v3_has_strict_rules(self):
        prompt = build_portscan_prompt_v3_hardened()
        assert "STRICT RULES" in prompt
        assert "No HTML" in prompt
        assert "Indicator | Type | Context" in prompt
        assert "SYN Port Scan Detected" in prompt


# ─────────────────────────────────────────────────────────────────────
# 2. Markdown Structure Evaluation Tests
# ─────────────────────────────────────────────────────────────────────

class TestMarkdownStructure:
    """Test markdown layout parser and metrics calculation."""

    GOOD_OUTPUT = (
        "## Incident Overview\n\n"
        "A SQL Injection campaign was detected.\n\n"
        "## Attack Analysis\n\n"
        "- 320 attempts from 2 source IPs.\n\n"
        "## Indicators of Compromise\n\n"
        "| Indicator | Type | Context |\n"
        "|---|---|---|\n"
        "| 203.0.113.101 | IP | Attacker |\n\n"
        "## MITRE ATT&CK Mapping\n\n"
        "**T1190** — Exploit Public-Facing Application\n\n"
        "## Recommended Containment\n\n"
        "- Block the source IPs.\n"
    )

    BAD_OUTPUT_PREAMBLE = (
        "Here is the playbook summary you requested:\n\n"
        "## Incident Overview\n\nSome overview data.\n"
    )

    BAD_OUTPUT_HTML = (
        "<div>## Incident Overview</div>\n"
        "## Attack Analysis\n"
    )

    def test_good_output_structure(self):
        result = check_markdown_structure(self.GOOD_OUTPUT)
        assert result["starts_with_header"] is True
        assert result["has_no_html"] is True
        assert result["has_no_preamble"] is True
        assert result["section_coverage"] == 1.0
        assert result["has_markdown_table"] is True
        assert result["has_bullet_points"] is True
        assert result["has_bold_text"] is True

    def test_preamble_rejection(self):
        result = check_markdown_structure(self.BAD_OUTPUT_PREAMBLE)
        assert result["has_no_preamble"] is False

    def test_html_rejection(self):
        result = check_markdown_structure(self.BAD_OUTPUT_HTML)
        assert result["has_no_html"] is False

    def test_missing_sections(self):
        partial = "## Incident Overview\n\nOverview content.\n"
        result = check_markdown_structure(partial)
        assert result["section_coverage"] < 1.0
        assert "Attack Analysis" in result["sections_missing"]


# ─────────────────────────────────────────────────────────────────────
# 3. Factual Accuracy Tests
# ─────────────────────────────────────────────────────────────────────

class TestFactualAccuracy:
    """Validate detection of telemetry parameters and hallucinations."""

    SQLI_ACCURATE = (
        "The attack originated from 203.0.113.101 and 203.0.113.102 targeting "
        "port 8080 and /api/v1/users/login with 320 events. "
        "Maps to MITRE technique T1190."
    )

    SQLI_HALLUCINATED = (
        "The attack from 203.0.113.101 and 192.168.1.99 targeted port 8080. "
        "An database admin account was breached (CVE-2024-9999)."
    )

    PORTSCAN_ACCURATE = (
        "Source IP 198.51.100.50 conducted a SYN Scan probe across 85 ports. "
        "A total of 1500 scanning events occurred. Technique T1595.001."
    )

    def test_sqli_accurate_checks(self):
        res = check_factual_accuracy(self.SQLI_ACCURATE, "sqli")
        assert res["known_ips_coverage"] == 1.0
        assert res["has_fabricated_ips"] is False
        assert res["correct_port_referenced"] is True
        assert res["correct_technique_referenced"] is True
        assert res["correct_event_count"] is True
        assert res["correct_url_referenced"] is True

    def test_sqli_hallucinated_checks(self):
        res = check_factual_accuracy(self.SQLI_HALLUCINATED, "sqli")
        assert res["has_fabricated_ips"] is True
        assert "192.168.1.99" in res["fabricated_ips"]

    def test_portscan_accurate_checks(self):
        res = check_factual_accuracy(self.PORTSCAN_ACCURATE, "portscan")
        assert res["known_ips_coverage"] == 1.0
        assert res["has_fabricated_ips"] is False
        assert res["correct_port_referenced"] is True
        assert res["correct_technique_referenced"] is True
        assert res["correct_event_count"] is True


# ─────────────────────────────────────────────────────────────────────
# 4. Security Compliance Tests
# ─────────────────────────────────────────────────────────────────────

class TestSecurityCompliance:
    """Validate check mappings for incident response best practices."""

    SQLI_COMPLIANT = (
        "Immediately block attacker IPs. Enable WAF signatures to inspect payload patterns. "
        "Remediate endpoints to use parameterized SQL queries to sanitize inputs. "
        "Logs indicate Initial Access tactic. Deploy Snort rule signature."
    )

    PORTSCAN_COMPLIANT = (
        "Apply firewall block rules on the scanner source IP. Deploy active honeypot deception "
        "techniques on the subnets. Review capture logs of host probes. "
        "Tactic discovery. Update IDS rules."
    )

    def test_sqli_compliance(self):
        res = check_security_compliance(self.SQLI_COMPLIANT, "sqli")
        assert res["mentions_containment"] is True
        assert res["mentions_monitoring"] is True
        assert res["mentions_credential_or_app_hygiene"] is True
        assert res["mentions_mitre_tactic"] is True
        assert res["references_snort_or_ids"] is True

    def test_portscan_compliance(self):
        res = check_security_compliance(self.PORTSCAN_COMPLIANT, "portscan")
        assert res["mentions_containment"] is True
        assert res["mentions_monitoring"] is True
        assert res["mentions_credential_or_app_hygiene"] is True
        assert res["mentions_mitre_tactic"] is True
        assert res["references_snort_or_ids"] is True


# ─────────────────────────────────────────────────────────────────────
# 5. Composite Scoring Tests
# ─────────────────────────────────────────────────────────────────────

class TestCompositeScoring:
    """Validate grading boundaries and hallucination penalties."""

    def _perfect_inputs(self):
        structure = {
            "starts_with_header": True,
            "has_no_html": True,
            "has_no_preamble": True,
            "section_coverage": 1.0,
            "has_markdown_table": True,
            "has_bullet_points": True,
            "has_bold_text": True,
            "word_count": 300,
        }
        accuracy = {
            "known_ips_coverage": 1.0,
            "has_fabricated_ips": False,
            "correct_port_referenced": True,
            "correct_technique_referenced": True,
            "correct_event_count": True,
            "correct_url_referenced": True,
        }
        compliance = {
            "mentions_containment": True,
            "mentions_monitoring": True,
            "mentions_credential_or_app_hygiene": True,
            "mentions_mitre_tactic": True,
            "references_snort_or_ids": True,
        }
        return structure, accuracy, compliance

    def test_perfect_score(self):
        s, a, c = self._perfect_inputs()
        score, grade = compute_quality_score(s, a, c)
        assert score == 100.0
        assert grade == "A"

    def test_hallucination_penalty(self):
        s, a, c = self._perfect_inputs()
        a_hallucinated = dict(a, has_fabricated_ips=True)
        score_clean, _ = compute_quality_score(s, a, c)
        score_dirty, _ = compute_quality_score(s, a_hallucinated, c)
        assert score_clean - score_dirty == 10.0

    def test_grade_boundaries(self):
        s, a, c = self._perfect_inputs()
        c_partial = dict(c, mentions_monitoring=False, references_snort_or_ids=False)
        score, grade = compute_quality_score(s, a, c_partial)
        assert score == 90.0
        assert grade == "A"

        c_poor = dict(c_partial, mentions_mitre_tactic=False, mentions_containment=False)
        score2, grade2 = compute_quality_score(s, a, c_poor)
        assert score2 < 90.0
        assert grade2 != "A"


# ─────────────────────────────────────────────────────────────────────
# 6. Telemetry Context Integrity
# ─────────────────────────────────────────────────────────────────────

class TestTelemetryContext:
    """Ensure RFC 5737 documentation ranges and mapping integrity."""

    def test_sqli_ips_rfc5737(self):
        for ip in SQLI_TELEMETRY_CONTEXT["source_ips"]:
            assert ip.startswith("203.0.113.") or ip.startswith("198.51.100.")

    def test_portscan_ips_rfc5737(self):
        for ip in PORTSCAN_TELEMETRY_CONTEXT["source_ips"]:
            assert ip.startswith("203.0.113.") or ip.startswith("198.51.100.")

    def test_mitre_technique_formats(self):
        assert re.match(r"^T\d{4}(?:\.\d{3})?$", SQLI_TELEMETRY_CONTEXT["mitre_technique_id"])
        assert re.match(r"^T\d{4}(?:\.\d{3})?$", PORTSCAN_TELEMETRY_CONTEXT["mitre_technique_id"])
