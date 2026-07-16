"""
tests/test_week17_day2_prompt_templates.py
-------------------------------------------
Week 17, Day 2 — Unit Tests for Structured Prompt Templates

Validates:
  1. normalise_utc_timestamp()  — UTC timestamp standardisation
  2. build_narrative_prompt()   — 4-section structured prompt construction
  3. render_narrative_prompt_jinja() — Jinja2 template rendering
  4. get_mitigation_steps()     — service-specific mitigation presets
  5. LLMService._build_context_prompt() — integration with structured prompts
  6. All four required sections present in generated prompts
"""

import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

os.environ["ENVIRONMENT"] = "test"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sentinel.prompt_templates import (
    normalise_utc_timestamp,
    build_narrative_prompt,
    render_narrative_prompt_jinja,
    get_mitigation_steps,
    SECTION_CAMPAIGN_CLUSTER_METADATA,
    SECTION_SOURCE_IPS_IOCS,
    SECTION_MITRE_ATTACK_MAPPING,
    SECTION_MITIGATION_STEPS,
    FULL_NARRATIVE_PROMPT_TEMPLATE,
    SYSTEM_INSTRUCTION_HEADER,
    _MITIGATION_PRESETS,
)

# ---------------------------------------------------------------------------
# Shared test context
# ---------------------------------------------------------------------------

SAMPLE_CONTEXT = {
    "campaign_id": "TEST-SSH-BF-001",
    "generated_at": "2026-07-14T10:00:00+05:30",
    "event_count": 150,
    "service_type": "SSH",
    "protocol": "TCP",
    "target_ports": [2222],
    "confidence_score": 0.8752,
    "severity": "CRITICAL",
    "time_range_start": "2026-07-14T08:00:00+05:30",
    "time_range_end": "2026-07-14T09:00:00+05:30",
    "source_ips": ["10.0.0.1", "10.0.0.2"],
    "ioc_entries": [
        {"type": "ip", "value": "10.0.0.1", "threat_level": "High"},
        {"type": "ip", "value": "10.0.0.2", "threat_level": "Medium"},
    ],
    "technique_id": "T1110.001",
    "technique_name": "Brute Force: Password Guessing",
    "tactic": "Credential Access",
    "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
    "threat_score": 87.5,
    "all_techniques": [
        {
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
        }
    ],
}


# ===========================================================================
# 1. UTC Timestamp Normalisation
# ===========================================================================

class TestNormaliseUtcTimestamp(unittest.TestCase):
    """Verify normalise_utc_timestamp() produces correct UTC ISO-8601 strings."""

    def test_iso_string_with_positive_offset(self):
        result = normalise_utc_timestamp("2026-07-14T10:00:00+05:30")
        self.assertEqual(result, "2026-07-14T04:30:00Z")

    def test_iso_string_with_z_suffix(self):
        result = normalise_utc_timestamp("2026-07-14T10:00:00Z")
        self.assertEqual(result, "2026-07-14T10:00:00Z")

    def test_naive_datetime_assumed_utc(self):
        dt = datetime(2026, 7, 14, 10, 0, 0)
        result = normalise_utc_timestamp(dt)
        self.assertEqual(result, "2026-07-14T10:00:00Z")

    def test_aware_datetime_converted_to_utc(self):
        tz_ist = timezone(timedelta(hours=5, minutes=30))
        dt = datetime(2026, 7, 14, 10, 0, 0, tzinfo=tz_ist)
        result = normalise_utc_timestamp(dt)
        self.assertEqual(result, "2026-07-14T04:30:00Z")

    def test_none_returns_current_utc(self):
        result = normalise_utc_timestamp(None)
        self.assertTrue(result.endswith("Z"))
        self.assertRegex(result, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_none_fallback_false_returns_na(self):
        result = normalise_utc_timestamp(None, fallback_now=False)
        self.assertEqual(result, "N/A")

    def test_empty_string_returns_current_utc(self):
        result = normalise_utc_timestamp("")
        self.assertTrue(result.endswith("Z"))

    def test_date_only_string(self):
        result = normalise_utc_timestamp("2026-07-14")
        self.assertEqual(result, "2026-07-14T00:00:00Z")

    def test_output_format_is_iso8601_utc(self):
        result = normalise_utc_timestamp("2026-01-01T00:00:00Z")
        self.assertRegex(result, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_negative_offset(self):
        result = normalise_utc_timestamp("2026-07-14T00:00:00-05:00")
        self.assertEqual(result, "2026-07-14T05:00:00Z")


# ===========================================================================
# 2. Module Constants
# ===========================================================================

class TestModuleConstants(unittest.TestCase):
    """Verify all required module-level constants exist and are non-empty."""

    def test_section_campaign_cluster_metadata_exists(self):
        self.assertIsInstance(SECTION_CAMPAIGN_CLUSTER_METADATA, str)
        self.assertGreater(len(SECTION_CAMPAIGN_CLUSTER_METADATA), 0)

    def test_section_source_ips_iocs_exists(self):
        self.assertIsInstance(SECTION_SOURCE_IPS_IOCS, str)
        self.assertGreater(len(SECTION_SOURCE_IPS_IOCS), 0)

    def test_section_mitre_attack_mapping_exists(self):
        self.assertIsInstance(SECTION_MITRE_ATTACK_MAPPING, str)
        self.assertGreater(len(SECTION_MITRE_ATTACK_MAPPING), 0)

    def test_section_mitigation_steps_exists(self):
        self.assertIsInstance(SECTION_MITIGATION_STEPS, str)
        self.assertGreater(len(SECTION_MITIGATION_STEPS), 0)

    def test_full_narrative_prompt_template_exists(self):
        self.assertIsInstance(FULL_NARRATIVE_PROMPT_TEMPLATE, str)
        self.assertGreater(len(FULL_NARRATIVE_PROMPT_TEMPLATE), 0)

    def test_system_instruction_header_contains_analyst_role(self):
        self.assertIn("cybersecurity", SYSTEM_INSTRUCTION_HEADER.lower())

    def test_mitigation_presets_cover_all_services(self):
        for service in ("SSH", "HTTP", "FTP", "SMTP", "PORT_SCAN", "UNKNOWN"):
            self.assertIn(service, _MITIGATION_PRESETS)

    def test_full_template_contains_all_four_sections(self):
        self.assertIn("Campaign Cluster Metadata", FULL_NARRATIVE_PROMPT_TEMPLATE)
        self.assertIn("Source IPs", FULL_NARRATIVE_PROMPT_TEMPLATE)
        self.assertIn("MITRE ATT&CK", FULL_NARRATIVE_PROMPT_TEMPLATE)
        self.assertIn("Mitigation Steps", FULL_NARRATIVE_PROMPT_TEMPLATE)


# ===========================================================================
# 3. get_mitigation_steps()
# ===========================================================================

class TestGetMitigationSteps(unittest.TestCase):
    """Verify service-specific mitigation presets are returned correctly."""

    def test_ssh_mitigation_contains_block_ips(self):
        steps = get_mitigation_steps("SSH")
        self.assertIn("Block Source IPs", steps)
        self.assertIn("SSH", steps)

    def test_http_mitigation_contains_waf(self):
        steps = get_mitigation_steps("HTTP")
        self.assertIn("WAF", steps)

    def test_ftp_mitigation_contains_anonymous(self):
        steps = get_mitigation_steps("FTP")
        self.assertIn("Anonymous FTP", steps)

    def test_smtp_mitigation_contains_spf(self):
        steps = get_mitigation_steps("SMTP")
        self.assertIn("SPF", steps)

    def test_unknown_service_returns_generic_steps(self):
        steps = get_mitigation_steps("UNKNOWN")
        self.assertIn("Block Source IPs", steps)

    def test_case_insensitive_lookup(self):
        steps_lower = get_mitigation_steps("ssh")
        steps_upper = get_mitigation_steps("SSH")
        self.assertEqual(steps_lower, steps_upper)

    def test_unrecognised_service_returns_generic(self):
        steps = get_mitigation_steps("TELNET")
        self.assertIn("Block Source IPs", steps)

    def test_each_preset_is_numbered_list(self):
        for service in ("SSH", "HTTP", "FTP", "SMTP", "UNKNOWN"):
            steps = get_mitigation_steps(service)
            self.assertIn("1.", steps)
            self.assertIn("2.", steps)


# ===========================================================================
# 4. build_narrative_prompt()
# ===========================================================================

class TestBuildNarrativePrompt(unittest.TestCase):
    """Verify the programmatic prompt builder produces correct output."""

    def setUp(self):
        self.prompt = build_narrative_prompt(SAMPLE_CONTEXT)

    def test_returns_non_empty_string(self):
        self.assertIsInstance(self.prompt, str)
        self.assertGreater(len(self.prompt), 100)

    def test_contains_section_1_campaign_metadata(self):
        self.assertIn("Campaign Cluster Metadata", self.prompt)
        self.assertIn("TEST-SSH-BF-001", self.prompt)

    def test_contains_section_2_source_ips(self):
        self.assertIn("Source IPs", self.prompt)
        self.assertIn("10.0.0.1", self.prompt)
        self.assertIn("10.0.0.2", self.prompt)

    def test_contains_section_3_mitre_mapping(self):
        self.assertIn("MITRE ATT&CK", self.prompt)
        self.assertIn("T1110.001", self.prompt)
        self.assertIn("Brute Force", self.prompt)
        self.assertIn("Credential Access", self.prompt)

    def test_contains_section_4_mitigation_steps(self):
        self.assertIn("Mitigation Steps", self.prompt)
        self.assertIn("Block Source IPs", self.prompt)

    def test_timestamp_is_utc(self):
        # The +05:30 offset input should appear as UTC in the prompt
        self.assertIn("2026-07-14T04:30:00Z", self.prompt)

    def test_time_range_start_normalised_to_utc(self):
        self.assertIn("2026-07-14T02:30:00Z", self.prompt)

    def test_ioc_table_present(self):
        self.assertIn("IOC", self.prompt)
        self.assertIn("High", self.prompt)

    def test_all_techniques_list_present(self):
        self.assertIn("T1110.001", self.prompt)

    def test_mitre_url_present(self):
        self.assertIn("attack.mitre.org", self.prompt)

    def test_confidence_score_present(self):
        self.assertIn("0.8752", self.prompt)

    def test_event_count_present(self):
        self.assertIn("150", self.prompt)

    def test_footer_contains_week17_day2(self):
        self.assertIn("Week 17, Day 2", self.prompt)

    def test_empty_source_ips_handled(self):
        ctx = dict(SAMPLE_CONTEXT, source_ips=[])
        prompt = build_narrative_prompt(ctx)
        self.assertIn("No source IPs", prompt)

    def test_missing_ioc_entries_handled(self):
        ctx = dict(SAMPLE_CONTEXT, ioc_entries=[])
        prompt = build_narrative_prompt(ctx)
        self.assertIsInstance(prompt, str)
        self.assertGreater(len(prompt), 0)

    def test_missing_all_techniques_handled(self):
        ctx = dict(SAMPLE_CONTEXT, all_techniques=[])
        prompt = build_narrative_prompt(ctx)
        self.assertIn("No additional technique", prompt)

    def test_minimal_context_no_crash(self):
        prompt = build_narrative_prompt({"campaign_id": "MINI-001"})
        self.assertIsInstance(prompt, str)
        self.assertIn("MINI-001", prompt)

    def test_http_mitigation_for_http_service(self):
        ctx = dict(SAMPLE_CONTEXT, service_type="HTTP")
        prompt = build_narrative_prompt(ctx)
        self.assertIn("WAF", prompt)

    def test_ftp_mitigation_for_ftp_service(self):
        ctx = dict(SAMPLE_CONTEXT, service_type="FTP")
        prompt = build_narrative_prompt(ctx)
        self.assertIn("Anonymous FTP", prompt)

    def test_port_scan_mitigation_for_port_scan_service(self):
        ctx = dict(SAMPLE_CONTEXT, service_type="PORT_SCAN")
        prompt = build_narrative_prompt(ctx)
        self.assertIn("Deception Honeypots", prompt)
        
        prompt_jinja = render_narrative_prompt_jinja(ctx)
        self.assertIn("Deception Honeypots", prompt_jinja)


# ===========================================================================
# 5. render_narrative_prompt_jinja()
# ===========================================================================

class TestRenderNarrativePromptJinja(unittest.TestCase):
    """Verify the Jinja2 template renders correctly."""

    def setUp(self):
        self.prompt = render_narrative_prompt_jinja(SAMPLE_CONTEXT)

    def test_returns_non_empty_string(self):
        self.assertIsInstance(self.prompt, str)
        self.assertGreater(len(self.prompt), 100)

    def test_contains_campaign_id(self):
        self.assertIn("TEST-SSH-BF-001", self.prompt)

    def test_contains_source_ips_section(self):
        self.assertIn("10.0.0.1", self.prompt)

    def test_contains_mitre_technique(self):
        self.assertIn("T1110.001", self.prompt)

    def test_contains_mitigation_section(self):
        self.assertIn("Mitigation", self.prompt)

    def test_timestamp_is_utc(self):
        self.assertIn("2026-07-14T04:30:00Z", self.prompt)

    def test_no_unrendered_jinja_tags(self):
        self.assertNotIn("{{", self.prompt)
        self.assertNotIn("}}", self.prompt)
        self.assertNotIn("{%", self.prompt)
        self.assertNotIn("%}", self.prompt)

    def test_fallback_on_missing_context_keys(self):
        minimal = {"campaign_id": "FALLBACK-001"}
        prompt = render_narrative_prompt_jinja(minimal)
        self.assertIsInstance(prompt, str)
        self.assertNotIn("{{", prompt)

    def test_all_four_section_headers_present(self):
        for heading in [
            "Campaign Cluster Metadata",
            "Source IPs",
            "MITRE ATT&CK",
            "Mitigation Steps",
        ]:
            self.assertIn(heading, self.prompt, f"Missing section: {heading}")

    def test_confidence_score_rendered(self):
        self.assertIn("0.8752", self.prompt)

    def test_event_count_rendered(self):
        self.assertIn("150", self.prompt)


# ===========================================================================
# 6. LLMService integration
# ===========================================================================

class TestLLMServicePromptIntegration(unittest.TestCase):
    """Verify LLMService._build_context_prompt uses structured templates."""

    def setUp(self):
        os.environ["SENTINEL_LLM_ENABLED"] = "false"
        from sentinel.llm_service import LLMService
        self.svc = LLMService()

    def test_build_context_prompt_returns_string(self):
        prompt = self.svc._build_context_prompt(SAMPLE_CONTEXT)
        self.assertIsInstance(prompt, str)
        self.assertGreater(len(prompt), 100)

    def test_structured_prompt_has_campaign_metadata_section(self):
        prompt = self.svc._build_context_prompt(SAMPLE_CONTEXT)
        self.assertIn("Campaign Cluster Metadata", prompt)

    def test_structured_prompt_has_source_ips_section(self):
        prompt = self.svc._build_context_prompt(SAMPLE_CONTEXT)
        self.assertIn("Source IPs", prompt)

    def test_structured_prompt_has_mitre_section(self):
        prompt = self.svc._build_context_prompt(SAMPLE_CONTEXT)
        self.assertIn("MITRE ATT&CK", prompt)

    def test_structured_prompt_has_mitigation_section(self):
        prompt = self.svc._build_context_prompt(SAMPLE_CONTEXT)
        self.assertIn("Mitigation", prompt)

    def test_legacy_keys_bridged(self):
        """src_ip + attack_type → source_ips + service_type bridge."""
        legacy_ctx = {
            "attack_type": "SSH_AUTH_FAILURE",
            "src_ip": "192.168.1.1",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "severity": "HIGH",
        }
        prompt = self.svc._build_context_prompt(legacy_ctx)
        self.assertIsInstance(prompt, str)
        self.assertGreater(len(prompt), 50)

    def test_generate_narrative_disabled_returns_empty(self):
        result = self.svc.generate_narrative(SAMPLE_CONTEXT)
        self.assertEqual(result, "")

    def test_build_prompt_minimal_context_no_crash(self):
        prompt = self.svc._build_context_prompt({})
        self.assertIsInstance(prompt, str)


# ===========================================================================
# 7. UTC timestamp standardisation across all prompt inputs
# ===========================================================================

class TestUTCTimestampStandardisation(unittest.TestCase):
    """Verify every time field in prompt output uses UTC ISO-8601 format."""

    def _check_no_offset_in_prompt(self, prompt: str):
        """Assert prompt contains no raw timezone offsets like +05:30."""
        import re
        # Raw offset patterns that should NOT appear unprocessed
        raw_offsets = re.findall(r"[+-]\d{2}:\d{2}", prompt)
        self.assertEqual(
            raw_offsets, [],
            f"Raw timezone offsets found in prompt: {raw_offsets}",
        )

    def test_build_prompt_no_raw_offsets(self):
        ctx = dict(
            SAMPLE_CONTEXT,
            generated_at="2026-07-14T15:50:00+05:30",
            time_range_start="2026-07-14T08:00:00+05:30",
            time_range_end="2026-07-14T09:00:00+05:30",
        )
        prompt = build_narrative_prompt(ctx)
        self._check_no_offset_in_prompt(prompt)

    def test_jinja_prompt_no_raw_offsets(self):
        ctx = dict(
            SAMPLE_CONTEXT,
            generated_at="2026-07-14T15:50:00+05:30",
            time_range_start="2026-07-14T08:00:00+05:30",
            time_range_end="2026-07-14T09:00:00+05:30",
        )
        prompt = render_narrative_prompt_jinja(ctx)
        self._check_no_offset_in_prompt(prompt)

    def test_utc_timestamps_end_with_z(self):
        ctx = dict(SAMPLE_CONTEXT, generated_at="2026-07-14T10:00:00+05:30")
        prompt = build_narrative_prompt(ctx)
        import re
        timestamps = re.findall(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", prompt)
        self.assertGreater(len(timestamps), 0, "No UTC timestamps found in prompt")

    def test_naive_datetime_treated_as_utc(self):
        ts = normalise_utc_timestamp("2026-07-14T12:00:00")
        self.assertEqual(ts, "2026-07-14T12:00:00Z")

    def test_aware_utc_datetime_unchanged(self):
        dt = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
        ts = normalise_utc_timestamp(dt)
        self.assertEqual(ts, "2026-07-14T12:00:00Z")


if __name__ == "__main__":
    unittest.main(verbosity=2)
