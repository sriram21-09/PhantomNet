#!/usr/bin/env python3
"""
tests/test_llm_quality_eval.py
-------------------------------
Unit tests for the LLM quality evaluation framework.
Validates prompt construction, markdown quality checks,
factual accuracy detection, and scoring logic — all offline,
no Ollama dependency required.
"""

import re
import sys
import os
import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.llm_ssh_brute_force_eval import (
    KNOWN_IPS,
    KNOWN_PORT,
    KNOWN_TECHNIQUE,
    REQUIRED_SECTIONS,
    SSH_TELEMETRY_CONTEXT,
    build_prompt_v1_raw,
    build_prompt_v2_structured,
    build_prompt_v3_hardened,
    check_factual_accuracy,
    check_markdown_structure,
    check_security_compliance,
    compute_quality_score,
)


# ─────────────────────────────────────────────────────────────────────
# 1. Prompt Construction Tests
# ─────────────────────────────────────────────────────────────────────

class TestPromptConstruction:
    """Verify all three prompt variants contain required telemetry."""

    def test_v1_contains_all_ips(self):
        prompt = build_prompt_v1_raw()
        for ip in SSH_TELEMETRY_CONTEXT["source_ips"]:
            assert ip in prompt, f"V1 prompt missing IP: {ip}"

    def test_v1_contains_technique(self):
        prompt = build_prompt_v1_raw()
        assert "T1110.001" in prompt

    def test_v1_contains_event_count(self):
        prompt = build_prompt_v1_raw()
        assert "450" in prompt

    def test_v2_has_telemetry_fences(self):
        prompt = build_prompt_v2_structured()
        assert "--- BEGIN TELEMETRY ---" in prompt
        assert "--- END TELEMETRY ---" in prompt

    def test_v2_specifies_sections(self):
        prompt = build_prompt_v2_structured()
        for section in REQUIRED_SECTIONS:
            assert section in prompt, f"V2 prompt missing section spec: {section}"

    def test_v2_anti_hallucination_instruction(self):
        prompt = build_prompt_v2_structured()
        assert "Do NOT fabricate" in prompt

    def test_v3_has_strict_rules(self):
        prompt = build_prompt_v3_hardened()
        assert "STRICT RULES" in prompt

    def test_v3_has_word_limit(self):
        prompt = build_prompt_v3_hardened()
        assert "500 words" in prompt

    def test_v3_has_table_instruction(self):
        prompt = build_prompt_v3_hardened()
        assert "Indicator | Type | Context" in prompt

    def test_v3_contains_snort_rule(self):
        prompt = build_prompt_v3_hardened()
        assert "alert tcp" in prompt

    def test_all_prompts_start_with_system(self):
        for builder in [build_prompt_v1_raw, build_prompt_v2_structured, build_prompt_v3_hardened]:
            prompt = builder()
            assert prompt.startswith("You are an expert"), (
                f"Prompt from {builder.__name__} doesn't start with system instructions"
            )

    def test_all_prompts_contain_campaign_id(self):
        for builder in [build_prompt_v1_raw, build_prompt_v2_structured, build_prompt_v3_hardened]:
            prompt = builder()
            assert "CAMP-W17-SSH-BF-001" in prompt


# ─────────────────────────────────────────────────────────────────────
# 2. Markdown Structure Evaluation Tests
# ─────────────────────────────────────────────────────────────────────

class TestMarkdownStructure:
    """Test the markdown quality checker against known inputs."""

    GOOD_OUTPUT = (
        "## Incident Overview\n\n"
        "A coordinated **SSH brute force** campaign was detected.\n\n"
        "## Attack Analysis\n\n"
        "- 450 failed login attempts from 3 source IPs\n"
        "- 120 unique usernames attempted\n\n"
        "## Indicators of Compromise\n\n"
        "| Indicator | Type | Context |\n"
        "|-----------|------|---------|\n"
        "| 203.0.113.45 | IP | Primary attacker |\n\n"
        "## MITRE ATT&CK Mapping\n\n"
        "**T1110.001** — Brute Force: Password Guessing\n\n"
        "## Recommended Containment\n\n"
        "- Block source IPs at the perimeter firewall\n"
        "- Enforce MFA on SSH services\n"
    )

    BAD_OUTPUT_PREAMBLE = (
        "Sure, here is your playbook summary:\n\n"
        "## Incident Overview\n\nSome content.\n"
    )

    BAD_OUTPUT_HTML = (
        "<div>## Incident Overview</div>\n"
        "<span>Attack analysis</span>\n"
    )

    def test_good_output_starts_with_header(self):
        result = check_markdown_structure(self.GOOD_OUTPUT)
        assert result["starts_with_header"] is True

    def test_good_output_no_html(self):
        result = check_markdown_structure(self.GOOD_OUTPUT)
        assert result["has_no_html"] is True

    def test_good_output_no_preamble(self):
        result = check_markdown_structure(self.GOOD_OUTPUT)
        assert result["has_no_preamble"] is True

    def test_good_output_all_sections(self):
        result = check_markdown_structure(self.GOOD_OUTPUT)
        assert result["section_coverage"] == 1.0
        assert len(result["sections_missing"]) == 0

    def test_good_output_has_table(self):
        result = check_markdown_structure(self.GOOD_OUTPUT)
        assert result["has_markdown_table"] is True

    def test_good_output_has_bullets(self):
        result = check_markdown_structure(self.GOOD_OUTPUT)
        assert result["has_bullet_points"] is True

    def test_good_output_has_bold(self):
        result = check_markdown_structure(self.GOOD_OUTPUT)
        assert result["has_bold_text"] is True

    def test_bad_preamble_detected(self):
        result = check_markdown_structure(self.BAD_OUTPUT_PREAMBLE)
        assert result["has_no_preamble"] is False

    def test_bad_html_detected(self):
        result = check_markdown_structure(self.BAD_OUTPUT_HTML)
        assert result["has_no_html"] is False

    def test_missing_sections_detected(self):
        partial = "## Incident Overview\n\nSome text.\n"
        result = check_markdown_structure(partial)
        assert result["section_coverage"] < 1.0
        assert len(result["sections_missing"]) > 0


# ─────────────────────────────────────────────────────────────────────
# 3. Factual Accuracy Tests
# ─────────────────────────────────────────────────────────────────────

class TestFactualAccuracy:
    """Validate hallucination detection logic."""

    ACCURATE_TEXT = (
        "The attack originated from 203.0.113.45, 203.0.113.46, and 198.51.100.77 "
        "targeting port 2222 with 450 failed logins using 120 unique usernames. "
        "MITRE ATT&CK technique T1110.001 applies."
    )

    HALLUCINATED_TEXT = (
        "The attack from 203.0.113.45 and 10.20.30.40 targeted port 2222 "
        "with 450 attempts. Also observed from 55.66.77.88."
    )

    def test_accurate_text_all_ips(self):
        result = check_factual_accuracy(self.ACCURATE_TEXT)
        assert result["known_ips_coverage"] == 1.0

    def test_accurate_text_no_fabrication(self):
        result = check_factual_accuracy(self.ACCURATE_TEXT)
        assert result["has_fabricated_ips"] is False

    def test_accurate_text_port(self):
        result = check_factual_accuracy(self.ACCURATE_TEXT)
        assert result["correct_port_referenced"] is True

    def test_accurate_text_technique(self):
        result = check_factual_accuracy(self.ACCURATE_TEXT)
        assert result["correct_technique_referenced"] is True

    def test_accurate_text_event_count(self):
        result = check_factual_accuracy(self.ACCURATE_TEXT)
        assert result["correct_event_count"] is True

    def test_hallucinated_text_detects_fabrication(self):
        result = check_factual_accuracy(self.HALLUCINATED_TEXT)
        assert result["has_fabricated_ips"] is True
        assert "10.20.30.40" in result["fabricated_ips"] or "55.66.77.88" in result["fabricated_ips"]

    def test_empty_text(self):
        result = check_factual_accuracy("")
        assert result["known_ips_coverage"] == 0.0
        assert result["correct_port_referenced"] is False


# ─────────────────────────────────────────────────────────────────────
# 4. Security Compliance Tests
# ─────────────────────────────────────────────────────────────────────

class TestSecurityCompliance:
    """Verify compliance check detections."""

    COMPLIANT_TEXT = (
        "Block the attacker IPs at the firewall. Monitor SSH logs for continued attempts. "
        "Enforce MFA and key-based authentication. "
        "The attack maps to Credential Access tactic. Deploy Snort IDS signatures."
    )

    def test_mentions_containment(self):
        result = check_security_compliance(self.COMPLIANT_TEXT)
        assert result["mentions_containment"] is True

    def test_mentions_monitoring(self):
        result = check_security_compliance(self.COMPLIANT_TEXT)
        assert result["mentions_monitoring"] is True

    def test_mentions_credential_hygiene(self):
        result = check_security_compliance(self.COMPLIANT_TEXT)
        assert result["mentions_credential_hygiene"] is True

    def test_mentions_mitre_tactic(self):
        result = check_security_compliance(self.COMPLIANT_TEXT)
        assert result["mentions_mitre_tactic"] is True

    def test_references_ids(self):
        result = check_security_compliance(self.COMPLIANT_TEXT)
        assert result["references_snort_or_ids"] is True

    def test_empty_text_fails_all(self):
        result = check_security_compliance("")
        assert not any(result.values())


# ─────────────────────────────────────────────────────────────────────
# 5. Composite Scoring Tests
# ─────────────────────────────────────────────────────────────────────

class TestCompositeScoring:
    """Validate scoring and grading logic."""

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
            "correct_username_count": True,
        }
        compliance = {
            "mentions_containment": True,
            "mentions_monitoring": True,
            "mentions_credential_hygiene": True,
            "mentions_mitre_tactic": True,
            "references_snort_or_ids": True,
        }
        return structure, accuracy, compliance

    def test_perfect_score(self):
        s, a, c = self._perfect_inputs()
        score, grade = compute_quality_score(s, a, c)
        assert score == 100.0
        assert grade == "A"

    def test_zero_score(self):
        s = {k: False for k in ["starts_with_header", "has_no_html", "has_no_preamble",
                                  "has_markdown_table", "has_bullet_points", "has_bold_text"]}
        s["section_coverage"] = 0.0
        s["word_count"] = 10
        a = {"known_ips_coverage": 0.0, "has_fabricated_ips": True,
             "correct_port_referenced": False, "correct_technique_referenced": False,
             "correct_event_count": False, "correct_username_count": False}
        c = {k: False for k in ["mentions_containment", "mentions_monitoring",
                                  "mentions_credential_hygiene", "mentions_mitre_tactic",
                                  "references_snort_or_ids"]}
        score, grade = compute_quality_score(s, a, c)
        assert score == 0.0
        assert grade == "F"

    def test_grade_boundaries(self):
        s, a, c = self._perfect_inputs()
        # Grade A at 90+
        score, grade = compute_quality_score(s, a, c)
        assert grade == "A"

        # Grade B: remove enough compliance to drop below 90
        c2 = {**c, "mentions_containment": False, "mentions_monitoring": False,
              "mentions_credential_hygiene": False}
        score2, grade2 = compute_quality_score(s, a, c2)
        assert grade2 == "B"

    def test_hallucination_penalty(self):
        s, a, c = self._perfect_inputs()
        a_hallucinated = {**a, "has_fabricated_ips": True}
        score_clean, _ = compute_quality_score(s, a, c)
        score_dirty, _ = compute_quality_score(s, a_hallucinated, c)
        assert score_clean - score_dirty == 10.0


# ─────────────────────────────────────────────────────────────────────
# 6. Telemetry Context Integrity
# ─────────────────────────────────────────────────────────────────────

class TestTelemetryContext:
    """Ensure telemetry context matches PhantomNet standards."""

    def test_uses_rfc5737_ips(self):
        for ip in SSH_TELEMETRY_CONTEXT["source_ips"]:
            assert ip.startswith("203.0.113.") or ip.startswith("198.51.100."), (
                f"IP {ip} is not in RFC 5737 documentation range"
            )

    def test_port_is_ssh_honeypot(self):
        assert SSH_TELEMETRY_CONTEXT["destination_port"] == 2222

    def test_mitre_technique_correct(self):
        assert SSH_TELEMETRY_CONTEXT["mitre_technique_id"] == "T1110.001"
        assert "Brute Force" in SSH_TELEMETRY_CONTEXT["mitre_technique_name"]

    def test_campaign_id_format(self):
        cid = SSH_TELEMETRY_CONTEXT["campaign_id"]
        assert cid.startswith("CAMP-")
        assert "SSH" in cid

    def test_threat_score_range(self):
        score = SSH_TELEMETRY_CONTEXT["threat_score"]
        assert 0 <= score <= 100

    def test_confidence_range(self):
        conf = SSH_TELEMETRY_CONTEXT["confidence_score"]
        assert 0.0 <= conf <= 1.0
