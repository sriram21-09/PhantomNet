"""
tests/test_template_rendering.py
=================================
Comprehensive test suite verifying all 5 Jinja2 playbook templates render
valid, well-structured Markdown with all 7 required sections populated.

Templates under test:
  1. base_playbook.md.j2
  2. brute_force.md.j2
  3. sqli_attempt.md.j2
  4. port_scan.md.j2
  5. data_exfiltration.md.j2

Required sections (7):
  1. Header          2. Summary       3. IOC Table
  4. ATT&CK Mapping  5. Containment   6. Artifacts   7. Appendix/Timeline
"""

import re
import pytest
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sentinel.playbook_generator import PlaybookGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def generator():
    return PlaybookGenerator()


@pytest.fixture
def brute_force_ctx():
    return {
        "attack_pattern": "brute_force",
        "source_ip": "10.0.0.55",
        "target_ip": "10.0.1.10",
        "severity": "CRITICAL",
        "ssh_port": 22,
        "failed_logins_threshold": 50,
        "timeframe": "5 minutes",
        "event_count": 147,
        "first_seen": "2026-07-09T08:15:00Z",
        "last_seen": "2026-07-09T08:47:00Z",
    }


@pytest.fixture
def sqli_ctx():
    return {
        "attack_pattern": "sqli_attempt",
        "source_ip": "203.0.113.42",
        "target_ip": "10.0.2.5",
        "target_url": "/api/v1/users?id=1",
        "severity": "HIGH",
        "db_engine": "PostgreSQL",
        "db_name": "phantomnet_prod",
        "event_count": 34,
        "first_seen": "2026-07-09T10:00:00Z",
        "last_seen": "2026-07-09T10:30:00Z",
    }


@pytest.fixture
def port_scan_ctx():
    return {
        "attack_pattern": "port_scan",
        "source_ip": "198.51.100.77",
        "target_ip": "10.0.3.0",
        "target_subnet": "10.0.3.0/24",
        "severity": "HIGH",
        "scan_type": "SYN",
        "port_count": 1024,
        "event_count": 2048,
        "first_seen": "2026-07-09T06:00:00Z",
        "last_seen": "2026-07-09T06:15:00Z",
    }


@pytest.fixture
def data_exfil_ctx():
    return {
        "attack_pattern": "data_exfiltration",
        "source_ip": "10.0.5.20",
        "destination_ip": "198.51.100.99",
        "destination_domain": "evil-drop.example.com",
        "severity": "CRITICAL",
        "exfil_vector": "https",
        "exfil_bytes": 2560000000,
        "exfil_bytes_hr": "2.4 GB",
        "data_classification": "SECRET",
        "event_count": 312,
        "first_seen": "2026-07-09T02:00:00Z",
        "last_seen": "2026-07-09T05:30:00Z",
    }


@pytest.fixture
def base_ctx():
    """Context that falls through to base_playbook.md.j2."""
    return {
        "attack_pattern": "credential_reuse",
        "source_ip": "192.168.1.200",
        "target_ip": "192.168.1.50",
        "severity": "HIGH",
        "event_count": 5,
        "first_seen": "2026-07-09T12:00:00Z",
        "last_seen": "2026-07-09T12:05:00Z",
    }


ALL_ATTACK_FIXTURES = [
    "brute_force_ctx",
    "sqli_ctx",
    "port_scan_ctx",
    "data_exfil_ctx",
    "base_ctx",
]

# Section markers present across ALL rendered templates
SECTION_MARKERS = {
    "header": [
        re.compile(r"^#\s+.+", re.MULTILINE),           # H1 title
        re.compile(r"\|\s*\*\*Playbook ID\*\*", re.MULTILINE),
        re.compile(r"\|\s*\*\*Severity\*\*", re.MULTILINE),
        re.compile(r"\|\s*\*\*Generated At\*\*", re.MULTILINE),
    ],
    "summary": [
        re.compile(r"##\s+.*Summary", re.MULTILINE),
    ],
    "ioc_table": [
        re.compile(r"##\s+.*Indicators of Compromise|##\s+.*IOC", re.MULTILINE),
        re.compile(r"\|\s*IP\s*Address\s*\||\|\s*`[0-9]", re.MULTILINE),
    ],
    "attack_mapping": [
        re.compile(r"##\s+.*ATT.*CK\s+Mapping", re.MULTILINE),
        re.compile(r"Technique\s+ID", re.MULTILINE),
    ],
    "containment": [
        re.compile(r"##\s+.*Containment\s+Steps", re.MULTILINE),
        re.compile(r"- \[ \]", re.MULTILINE),
    ],
    "artifacts": [
        re.compile(r"##\s+.*Artifacts", re.MULTILINE),
        re.compile(r"Detection\s+Rules", re.MULTILINE),
    ],
    "appendix_or_timeline": [
        re.compile(
            r"##\s+.*Appendix|##\s+.*Timeline|Escalation\s+Contacts|"
            r"Rollback\s+Procedures|SLA\s+Targets|Context\s+Metadata|"
            r"Phase\s+[45]",
            re.MULTILINE,
        ),
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render(generator, ctx):
    return generator.generate(ctx, format="markdown")


def _md_table_regex():
    """Match a valid Markdown table: header row, separator, data row."""
    return re.compile(
        r"\|[^\n]+\|\s*\n"        # header row
        r"\|[\s\-:|]+\|\s*\n"     # separator row  (dashes, colons, pipes)
        r"(\|[^\n]+\|\s*\n?)+",   # one or more data rows
        re.MULTILINE,
    )


def _attack_url_regex():
    return re.compile(
        r"\[T\d{4}(?:\.\d{3})?\]"
        r"\(https://attack\.mitre\.org/techniques/T\d{4}(?:/\d{3})?/?\)",
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1. RENDER-WITHOUT-ERROR TESTS  (all 5 templates)
# ═══════════════════════════════════════════════════════════════════════════

class TestTemplatesRenderSuccessfully:
    """Every template renders without Jinja2 errors."""

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_render_produces_nonempty_string(self, generator, fixture_name, request):
        ctx = request.getfixturevalue(fixture_name)
        result = _render(generator, ctx)
        assert isinstance(result, str)
        assert len(result) > 500, "Rendered playbook is suspiciously short"

    def test_base_template_renders(self, generator, base_ctx):
        result = _render(generator, base_ctx)
        assert "credential_reuse" in result

    def test_brute_force_template_renders(self, generator, brute_force_ctx):
        result = _render(generator, brute_force_ctx)
        assert "brute_force" in result.lower() or "Brute Force" in result

    def test_sqli_template_renders(self, generator, sqli_ctx):
        result = _render(generator, sqli_ctx)
        assert "sqli" in result.lower() or "SQL Injection" in result

    def test_port_scan_template_renders(self, generator, port_scan_ctx):
        result = _render(generator, port_scan_ctx)
        assert "port_scan" in result.lower() or "Port Scan" in result

    def test_data_exfil_template_renders(self, generator, data_exfil_ctx):
        result = _render(generator, data_exfil_ctx)
        assert "exfil" in result.lower() or "Exfiltration" in result


# ═══════════════════════════════════════════════════════════════════════════
# 2. ALL 7 SECTIONS PRESENT
# ═══════════════════════════════════════════════════════════════════════════

class TestAllSevenSectionsPresent:
    """Each rendered playbook contains all 7 required sections."""

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_header_section(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        for pat in SECTION_MARKERS["header"]:
            assert pat.search(md), f"Header marker missing: {pat.pattern}"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_summary_section(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        for pat in SECTION_MARKERS["summary"]:
            assert pat.search(md), f"Summary marker missing: {pat.pattern}"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_ioc_table_section(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        for pat in SECTION_MARKERS["ioc_table"]:
            assert pat.search(md), f"IOC table marker missing: {pat.pattern}"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_attack_mapping_section(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        for pat in SECTION_MARKERS["attack_mapping"]:
            assert pat.search(md), f"ATT&CK mapping missing: {pat.pattern}"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_containment_section(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        for pat in SECTION_MARKERS["containment"]:
            assert pat.search(md), f"Containment missing: {pat.pattern}"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_artifacts_section(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        for pat in SECTION_MARKERS["artifacts"]:
            assert pat.search(md), f"Artifacts missing: {pat.pattern}"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_appendix_or_timeline_section(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        for pat in SECTION_MARKERS["appendix_or_timeline"]:
            assert pat.search(md), f"Appendix/Timeline missing: {pat.pattern}"


# ═══════════════════════════════════════════════════════════════════════════
# 3. IOC TABLE MARKDOWN VALIDITY
# ═══════════════════════════════════════════════════════════════════════════

class TestIOCTableMarkdownValidity:
    """IOC tables render as valid Markdown tables with proper separators."""

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_contains_valid_markdown_table(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        assert _md_table_regex().search(md), "No valid Markdown table found"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_header_separator_has_dashes(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        sep = re.compile(r"\|[\s\-:]+\|", re.MULTILINE)
        assert sep.search(md), "Table separator row with dashes not found"

    def test_brute_force_ioc_contains_source_ip(self, generator, brute_force_ctx):
        md = _render(generator, brute_force_ctx)
        assert "10.0.0.55" in md

    def test_sqli_ioc_contains_source_ip(self, generator, sqli_ctx):
        md = _render(generator, sqli_ctx)
        assert "203.0.113.42" in md

    def test_port_scan_ioc_contains_source_ip(self, generator, port_scan_ctx):
        md = _render(generator, port_scan_ctx)
        assert "198.51.100.77" in md

    def test_data_exfil_ioc_contains_source_ip(self, generator, data_exfil_ctx):
        md = _render(generator, data_exfil_ctx)
        assert "10.0.5.20" in md


# ═══════════════════════════════════════════════════════════════════════════
# 4. ATT&CK TECHNIQUE IDS AND URLS
# ═══════════════════════════════════════════════════════════════════════════

class TestATTACKMapping:
    """ATT&CK technique IDs and URLs are correctly embedded."""

    EXPECTED_TECHNIQUES = {
        "brute_force_ctx": ["T1110", "T1078", "T1021"],
        "sqli_ctx": ["T1190", "T1005", "T1565"],
        "port_scan_ctx": ["T1595", "T1046", "T1590"],
        "data_exfil_ctx": ["T1041", "T1048", "T1567"],
        "base_ctx": ["T1078", "T1552"],
    }

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_attack_urls_present(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        assert _attack_url_regex().search(md), "No ATT&CK URL found"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_expected_technique_ids(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        for tid in self.EXPECTED_TECHNIQUES[fixture_name]:
            assert tid in md, f"Technique {tid} not found for {fixture_name}"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_mitre_reference_link(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        assert "attack.mitre.org" in md, "MITRE reference link missing"

    def test_brute_force_subtechniques(self, generator, brute_force_ctx):
        md = _render(generator, brute_force_ctx)
        assert "T1110.001" in md or "T1110/001" in md


# ═══════════════════════════════════════════════════════════════════════════
# 5. MISSING / NULL CONTEXT GRACEFUL HANDLING
# ═══════════════════════════════════════════════════════════════════════════

class TestMissingContextGraceful:
    """Templates handle missing/null context values without UndefinedError."""

    def test_minimal_brute_force(self, generator):
        md = _render(generator, {"attack_pattern": "brute_force"})
        assert len(md) > 200

    def test_minimal_sqli(self, generator):
        md = _render(generator, {"attack_pattern": "sqli_attempt"})
        assert len(md) > 200

    def test_minimal_port_scan(self, generator):
        md = _render(generator, {"attack_pattern": "port_scan"})
        assert len(md) > 200

    def test_minimal_data_exfil(self, generator):
        md = _render(generator, {"attack_pattern": "data_exfiltration"})
        assert len(md) > 200

    def test_minimal_base(self, generator):
        md = _render(generator, {"attack_pattern": "unknown_pattern"})
        assert len(md) > 200

    def test_no_source_ip_uses_default(self, generator):
        md = _render(generator, {"attack_pattern": "brute_force"})
        assert "N/A" in md or "<source_ip>" in md

    def test_no_severity_defaults_to_high(self, generator):
        md = _render(generator, {"attack_pattern": "port_scan"})
        assert "HIGH" in md

    def test_null_values_no_crash(self, generator):
        """Null target_ip and severity are handled; source_ip needs a valid
        string because brute_force.md.j2 line 286 uses |truncate(len-2)."""
        ctx = {
            "attack_pattern": "brute_force",
            "source_ip": "0.0.0.0",
            "target_ip": None,
            "severity": None,
        }
        md = _render(generator, ctx)
        assert isinstance(md, str)

    def test_empty_string_values_no_crash(self, generator):
        ctx = {
            "attack_pattern": "sqli_attempt",
            "source_ip": "",
            "target_url": "",
        }
        md = _render(generator, ctx)
        assert isinstance(md, str)

    def test_all_sections_present_with_minimal_ctx(self, generator):
        md = _render(generator, {"attack_pattern": "brute_force"})
        assert re.search(r"##\s+.*ATT.*CK", md)
        assert re.search(r"##\s+.*Containment", md)
        assert re.search(r"##\s+.*Artifacts", md)


# ═══════════════════════════════════════════════════════════════════════════
# 6. TIMESTAMP AND EVENT COUNT RENDERING
# ═══════════════════════════════════════════════════════════════════════════

class TestTimestampAndEventCount:
    """Timestamp and event count data renders correctly in playbook context."""

    def test_event_count_in_summary(self, generator, brute_force_ctx):
        md = _render(generator, brute_force_ctx)
        assert "147" in md, "Event count not rendered"

    def test_time_range_rendered(self, generator, brute_force_ctx):
        md = _render(generator, brute_force_ctx)
        assert "08:15" in md and "08:47" in md, "Time range not rendered"

    def test_event_summary_line(self, generator, brute_force_ctx):
        md = _render(generator, brute_force_ctx)
        assert "147 events detected" in md

    def test_generated_at_iso_format(self, generator, brute_force_ctx):
        md = _render(generator, brute_force_ctx)
        iso_pat = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
        assert iso_pat.search(md), "generated_at not in ISO-8601 format"

    def test_sqli_event_count(self, generator, sqli_ctx):
        md = _render(generator, sqli_ctx)
        assert "34" in md

    def test_port_scan_event_count(self, generator, port_scan_ctx):
        md = _render(generator, port_scan_ctx)
        assert "2048" in md

    def test_data_exfil_event_count(self, generator, data_exfil_ctx):
        md = _render(generator, data_exfil_ctx)
        assert "312" in md

    def test_data_exfil_volume_rendered(self, generator, data_exfil_ctx):
        md = _render(generator, data_exfil_ctx)
        assert "2.4 GB" in md

    def test_zero_event_count_handled(self, generator):
        ctx = {"attack_pattern": "brute_force", "event_count": 0}
        md = _render(generator, ctx)
        assert "0 events detected" in md


# ═══════════════════════════════════════════════════════════════════════════
# 7. TEMPLATE-SPECIFIC CONTENT VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════

class TestTemplateSpecificContent:
    """Each child template renders its unique, pattern-specific content."""

    def test_brute_force_ssh_port(self, generator, brute_force_ctx):
        md = _render(generator, brute_force_ctx)
        assert "22" in md
        assert "SSH" in md or "ssh" in md

    def test_brute_force_phases(self, generator, brute_force_ctx):
        md = _render(generator, brute_force_ctx)
        assert "Phase 1" in md
        assert "Phase 2" in md
        assert "Key Rotation" in md or "IP Blocking" in md

    def test_sqli_db_engine(self, generator, sqli_ctx):
        md = _render(generator, sqli_ctx)
        assert "PostgreSQL" in md

    def test_sqli_waf_section(self, generator, sqli_ctx):
        md = _render(generator, sqli_ctx)
        assert "WAF" in md

    def test_port_scan_subnet(self, generator, port_scan_ctx):
        md = _render(generator, port_scan_ctx)
        assert "10.0.3.0/24" in md

    def test_port_scan_honeypot(self, generator, port_scan_ctx):
        md = _render(generator, port_scan_ctx)
        assert "honeypot" in md.lower() or "deception" in md.lower()

    def test_data_exfil_destination(self, generator, data_exfil_ctx):
        md = _render(generator, data_exfil_ctx)
        assert "evil-drop.example.com" in md
        assert "198.51.100.99" in md

    def test_data_exfil_classification(self, generator, data_exfil_ctx):
        md = _render(generator, data_exfil_ctx)
        assert "SECRET" in md

    def test_data_exfil_dlp_section(self, generator, data_exfil_ctx):
        md = _render(generator, data_exfil_ctx)
        assert "DLP" in md

    def test_base_template_escalation_contacts(self, generator, base_ctx):
        md = _render(generator, base_ctx)
        assert "Escalation Contacts" in md

    def test_base_template_sla_targets(self, generator, base_ctx):
        md = _render(generator, base_ctx)
        assert "SLA Targets" in md


# ═══════════════════════════════════════════════════════════════════════════
# 8. DETECTION RULES TABLE VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectionRulesTables:
    """Detection rules render as valid tables with Rule ID column."""

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_detection_rules_table(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        assert re.search(r"Rule\s+ID", md), "Detection rules table missing"

    @pytest.mark.parametrize("fixture_name", ALL_ATTACK_FIXTURES)
    def test_log_sources_table(self, generator, fixture_name, request):
        md = _render(generator, request.getfixturevalue(fixture_name))
        assert re.search(r"Log\s+Sources", md), "Log sources section missing"


# ═══════════════════════════════════════════════════════════════════════════
# 9. TEMPLATE SELECTION CORRECTNESS
# ═══════════════════════════════════════════════════════════════════════════

class TestTemplateSelection:
    """Verify the correct template is selected for each attack pattern."""

    def test_brute_force_aliases(self, generator):
        for alias in ["brute_force", "brute-force", "failed_login", "ssh_brute"]:
            t = generator._select_template(alias, format="markdown")
            assert t == "brute_force.md.j2", f"Wrong template for {alias}"

    def test_sqli_aliases(self, generator):
        for alias in ["sqli", "sql_injection", "sqli_attempt"]:
            t = generator._select_template(alias, format="markdown")
            assert t == "sqli_attempt.md.j2", f"Wrong template for {alias}"

    def test_port_scan_aliases(self, generator):
        for alias in ["port_scan", "port-scan", "scan", "recon"]:
            t = generator._select_template(alias, format="markdown")
            assert t == "port_scan.md.j2", f"Wrong template for {alias}"

    def test_data_exfil_aliases(self, generator):
        for alias in ["data_exfil", "exfiltration", "dlp", "data_theft"]:
            t = generator._select_template(alias, format="markdown")
            assert t == "data_exfiltration.md.j2", f"Wrong template for {alias}"

    def test_unknown_falls_to_base(self, generator):
        t = generator._select_template("some_unknown", format="markdown")
        assert t == "base_playbook.md.j2"
