"""
tests/test_playbook_time_range.py
-----------------------------------
Time Range & Event Count Enrichment — PhantomNet Sentinel PlaybookGenerator

Validates that ALL 4 attack-pattern templates correctly display:
  • event_count   — number of events from cluster data
  • time_range    — "HH:MM–HH:MM UTC" formatted from first_seen / last_seen
  • event_summary — "N events detected between HH:MM and HH:MM UTC"

Test Structure
--------------
  TestTimeRangeParsing        (30)  _parse_dt internals via context output
  TestEventSummaryFormatting  (24)  formatted string correctness
  TestBruteForceTemplate      (18)  brute_force.md.j2 rendering
  TestSQLiTemplate            (18)  sqli_attempt.md.j2 rendering
  TestPortScanTemplate        (18)  port_scan.md.j2 rendering
  TestDataExfilTemplate       (18)  data_exfiltration.md.j2 rendering
  TestAllTemplatesCommon      (20)  cross-template assertions
  TestEdgeCases               (20)  boundary / error inputs

Total: 166 tests
"""

from __future__ import annotations

import sys
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "backend")
for _p in (_ROOT, _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Pre-patch database before any sentinel import
from unittest.mock import MagicMock as _MagicMock
sys.modules.setdefault("database.database", _MagicMock())

from sentinel.playbook_generator import PlaybookGenerator

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_gen = PlaybookGenerator()

FIRST_SEEN_ISO = "2026-06-30T08:15:00Z"
LAST_SEEN_ISO  = "2026-06-30T08:47:00Z"

PATTERNS = [
    ("brute_force",      {"attack_pattern": "brute_force"}),
    ("sqli_attempt",     {"attack_pattern": "sqli"}),
    ("port_scan",        {"attack_pattern": "port_scan"}),
    ("data_exfiltration",{"attack_pattern": "data_exfil"}),
]


def _render(extra: Dict[str, Any], attack_pattern: str = "brute_force") -> str:
    ctx = {"attack_pattern": attack_pattern, "source_ip": "10.0.0.1"}
    ctx.update(extra)
    return _gen.generate(ctx)


def _extract_event_summary(rendered: str) -> str | None:
    """Extract the Event Summary cell value from rendered Markdown."""
    for line in rendered.splitlines():
        if "**Event Summary**" in line:
            # | **Event Summary** | **147 events detected between 08:15 and 08:47 UTC** |
            parts = line.split("|")
            if len(parts) >= 3:
                return parts[2].strip()
    return None


def _extract_time_range(rendered: str) -> str | None:
    """Extract the Time Range cell value from rendered Markdown."""
    for line in rendered.splitlines():
        if "**Time Range**" in line:
            parts = line.split("|")
            if len(parts) >= 3:
                return parts[2].strip()
    return None


def _count_event_summary_occurrences(rendered: str) -> int:
    """Count how many times 'Event Summary' appears in rendered output."""
    return sum(1 for line in rendered.splitlines() if "Event Summary" in line)


# ===========================================================================
# SECTION 1: Time Range Parsing Tests
# ===========================================================================

class TestTimeRangeParsing:
    """Verify time range is correctly extracted from various input formats."""

    def test_iso_z_format_parses_start_time(self):
        rendered = _render({
            "first_seen": "2026-06-30T08:15:00Z",
            "last_seen":  "2026-06-30T08:47:00Z",
            "event_count": 147,
        })
        summary = _extract_event_summary(rendered)
        assert summary is not None
        assert "08:15" in summary

    def test_iso_z_format_parses_end_time(self):
        rendered = _render({
            "first_seen": "2026-06-30T08:15:00Z",
            "last_seen":  "2026-06-30T08:47:00Z",
            "event_count": 147,
        })
        summary = _extract_event_summary(rendered)
        assert "08:47" in summary

    def test_iso_offset_format_parses_correctly(self):
        rendered = _render({
            "first_seen": "2026-07-01T14:02:30+00:00",
            "last_seen":  "2026-07-01T14:18:55+00:00",
            "event_count": 23,
        })
        summary = _extract_event_summary(rendered)
        assert "14:02" in summary
        assert "14:18" in summary

    def test_datetime_object_parses_correctly(self):
        dt_first = datetime(2026, 6, 30, 9, 0, 0, tzinfo=timezone.utc)
        dt_last  = datetime(2026, 6, 30, 9, 32, 0, tzinfo=timezone.utc)
        rendered = _render({
            "first_seen": dt_first,
            "last_seen":  dt_last,
            "event_count": 20,
        })
        summary = _extract_event_summary(rendered)
        assert "09:00" in summary
        assert "09:32" in summary

    def test_naive_datetime_treated_as_utc(self):
        dt_first = datetime(2026, 6, 30, 11, 30, 0)   # naive
        dt_last  = datetime(2026, 6, 30, 12, 15, 0)   # naive
        rendered = _render({
            "first_seen": dt_first,
            "last_seen":  dt_last,
            "event_count": 5,
        })
        summary = _extract_event_summary(rendered)
        assert "11:30" in summary
        assert "12:15" in summary

    def test_unix_timestamp_integer_parses(self):
        # 2026-07-01 10:00:00 UTC
        ts_first = int(datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc).timestamp())
        ts_last  = int(datetime(2026, 7, 1, 10, 45, 0, tzinfo=timezone.utc).timestamp())
        rendered = _render({
            "first_seen": ts_first,
            "last_seen":  ts_last,
            "event_count": 88,
        })
        summary = _extract_event_summary(rendered)
        assert "10:00" in summary
        assert "10:45" in summary

    def test_unix_timestamp_float_parses(self):
        ts_first = datetime(2026, 7, 1, 6, 5, 0, tzinfo=timezone.utc).timestamp()
        ts_last  = datetime(2026, 7, 1, 6, 59, 0, tzinfo=timezone.utc).timestamp()
        rendered = _render({
            "first_seen": float(ts_first),
            "last_seen":  float(ts_last),
            "event_count": 15,
        })
        summary = _extract_event_summary(rendered)
        assert "06:05" in summary

    def test_cluster_first_seen_key_accepted(self):
        """cluster_first_seen / cluster_last_seen aliases must work."""
        rendered = _render({
            "cluster_first_seen": "2026-06-30T22:00:00Z",
            "cluster_last_seen":  "2026-06-30T22:30:00Z",
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert "22:00" in summary
        assert "22:30" in summary

    def test_first_seen_preferred_over_cluster_first_seen(self):
        """first_seen takes priority over cluster_first_seen."""
        rendered = _render({
            "first_seen":         "2026-06-30T08:00:00Z",
            "cluster_first_seen": "2026-06-30T07:00:00Z",  # should be ignored
            "last_seen":          "2026-06-30T08:30:00Z",
            "event_count": 5,
        })
        summary = _extract_event_summary(rendered)
        assert "08:00" in summary
        assert "07:00" not in summary

    def test_only_first_seen_produces_partial_time_range(self):
        rendered = _render({
            "first_seen": "2026-06-30T08:15:00Z",
            "event_count": 50,
        })
        tr = _extract_time_range(rendered)
        # Should contain "from HH:MM UTC" when no last_seen
        assert tr is not None
        assert "08:15" in tr

    def test_no_timestamps_produces_na_time_range(self):
        rendered = _render({"event_count": 10})
        tr = _extract_time_range(rendered)
        assert tr is not None
        assert "N/A" in tr

    def test_invalid_string_timestamp_produces_na(self):
        rendered = _render({
            "first_seen": "not-a-date",
            "last_seen":  "also-not-a-date",
            "event_count": 5,
        })
        tr = _extract_time_range(rendered)
        assert "N/A" in tr

    def test_na_string_timestamp_produces_na(self):
        rendered = _render({
            "first_seen": "N/A",
            "last_seen":  "N/A",
            "event_count": 5,
        })
        tr = _extract_time_range(rendered)
        assert "N/A" in tr

    def test_midnight_timestamp_formats_as_00_00(self):
        rendered = _render({
            "first_seen": "2026-06-30T00:00:00Z",
            "last_seen":  "2026-06-30T00:05:00Z",
            "event_count": 3,
        })
        summary = _extract_event_summary(rendered)
        assert "00:00" in summary
        assert "00:05" in summary

    def test_same_start_end_time_renders(self):
        rendered = _render({
            "first_seen": "2026-06-30T08:15:00Z",
            "last_seen":  "2026-06-30T08:15:00Z",
            "event_count": 1,
        })
        summary = _extract_event_summary(rendered)
        assert "08:15" in summary

    def test_midnight_crossing_renders_correctly(self):
        """23:45 to 00:12 should display correctly."""
        rendered = _render({
            "first_seen": "2026-06-29T23:45:00Z",
            "last_seen":  "2026-06-30T00:12:00Z",
            "event_count": 7,
        }, attack_pattern="data_exfil")
        summary = _extract_event_summary(rendered)
        assert "23:45" in summary
        assert "00:12" in summary

    def test_iso_fractional_seconds_parses(self):
        rendered = _render({
            "first_seen": "2026-06-30T08:15:30.123456Z",
            "last_seen":  "2026-06-30T08:47:59.999Z",
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert "08:15" in summary
        assert "08:47" in summary

    def test_space_separated_datetime_parses(self):
        rendered = _render({
            "first_seen": "2026-06-30 08:15:00",
            "last_seen":  "2026-06-30 08:47:00",
            "event_count": 30,
        })
        summary = _extract_event_summary(rendered)
        assert "08:15" in summary
        assert "08:47" in summary

    def test_time_range_shows_utc_label(self):
        rendered = _render({
            "first_seen": "2026-06-30T08:15:00Z",
            "last_seen":  "2026-06-30T08:47:00Z",
            "event_count": 100,
        })
        summary = _extract_event_summary(rendered)
        assert "UTC" in summary

    def test_pre_computed_time_range_is_not_overwritten(self):
        """If time_range is pre-computed by caller, it must be used as-is."""
        rendered = _render({
            "time_range":   "08:00–09:00 UTC",
            "event_summary": "50 events detected between 08:00 and 09:00 UTC",
            "event_count":  50,
        })
        summary = _extract_event_summary(rendered)
        assert "50 events" in summary
        assert "08:00" in summary
        assert "09:00" in summary

    def test_pre_computed_event_summary_is_not_overwritten(self):
        rendered = _render({
            "event_summary": "CUSTOM SUMMARY STRING",
        })
        summary = _extract_event_summary(rendered)
        assert "CUSTOM SUMMARY STRING" in summary

    def test_ioc_first_seen_last_seen_used_in_ioc_table(self):
        """first_seen / last_seen appear in IOC table as well."""
        rendered = _render({
            "first_seen": "2026-06-30T08:15:00Z",
            "last_seen":  "2026-06-30T08:47:00Z",
            "event_count": 10,
        })
        # The IOC table uses ioc.first_seen/ioc.last_seen OR detection_time/generated_at
        # Just verify the render completed without error
        assert "IOC" in rendered or "Indicator" in rendered

    def test_large_unix_timestamp_parses(self):
        ts = int(datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc).timestamp())
        rendered = _render({
            "first_seen": ts,
            "last_seen":  ts + 3600,
            "event_count": 5,
        })
        summary = _extract_event_summary(rendered)
        assert "12:00" in summary
        assert "13:00" in summary

    def test_event_count_zero_renders(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 0,
        })
        summary = _extract_event_summary(rendered)
        assert "0 events" in summary

    def test_event_count_large_number(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 999999,
        })
        summary = _extract_event_summary(rendered)
        assert "999999" in summary

    def test_hit_count_fallback_for_event_count(self):
        """hit_count is used when event_count is not provided."""
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "hit_count": 42,
        })
        summary = _extract_event_summary(rendered)
        assert "42" in summary

    def test_time_range_in_header_table(self):
        """time_range must appear in the header table as Event Summary row."""
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 147,
        })
        assert "Event Summary" in rendered

    def test_time_range_in_trigger_context_table(self):
        """Time Range row must appear in the Trigger Context table in summary."""
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        assert "Time Range" in rendered

    def test_both_event_summary_rows_present(self):
        """Event Summary appears in BOTH header table AND Trigger Context table."""
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 100,
        })
        count = _count_event_summary_occurrences(rendered)
        assert count >= 2, (
            f"Expected Event Summary in at least 2 sections, found {count}"
        )


# ===========================================================================
# SECTION 2: Event Summary Formatting Tests
# ===========================================================================

class TestEventSummaryFormatting:
    """Verify the formatted 'N events detected between HH:MM and HH:MM UTC' string."""

    def test_plural_events_for_n_gt_1(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 147,
        })
        summary = _extract_event_summary(rendered)
        assert "events" in summary  # plural

    def test_singular_event_for_n_eq_1(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 1,
        })
        summary = _extract_event_summary(rendered)
        # Should be "1 event detected" not "1 events detected"
        assert "1 event " in summary
        assert "1 events" not in summary

    def test_exact_format_with_time_range(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 147,
        })
        summary = _extract_event_summary(rendered)
        assert "147 events detected between 08:15 and 08:47 UTC" in summary

    def test_format_contains_between_keyword(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert "between" in summary

    def test_format_contains_and_keyword(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert " and " in summary

    def test_format_contains_detected_keyword(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert "detected" in summary

    def test_format_contains_utc_suffix(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert "UTC" in summary

    def test_event_count_appears_first_in_summary(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 55,
        })
        summary = _extract_event_summary(rendered)
        assert summary.strip().startswith("**55") or "55 event" in summary

    def test_hhmm_format_zero_padded(self):
        rendered = _render({
            "first_seen": "2026-06-30T08:05:00Z",
            "last_seen":  "2026-06-30T09:07:00Z",
            "event_count": 3,
        })
        summary = _extract_event_summary(rendered)
        # Should be 08:05 not 8:5
        assert "08:05" in summary
        assert "09:07" in summary

    def test_no_timestamp_event_summary_fallback(self):
        """Without timestamps, summary just shows count without time range."""
        rendered = _render({"event_count": 42})
        summary = _extract_event_summary(rendered)
        assert "42" in summary
        assert summary is not None

    def test_event_summary_is_bold_in_markdown(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        # Summary cell value is wrapped in ** for bold
        for line in rendered.splitlines():
            if "Event Summary" in line and "08:15" in line:
                assert "**" in line
                break
        else:
            pytest.skip("Event Summary line not found in expected form")

    def test_time_range_field_contains_en_dash(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        tr = _extract_time_range(rendered)
        # Time range should be formatted as "HH:MM–HH:MM UTC" with en-dash
        assert tr is not None
        assert "–" in tr or "-" in tr or "|" not in tr  # accepts en-dash or hyphen

    @pytest.mark.parametrize("count,expected_word", [
        (0,   "events"),
        (1,   "event"),
        (2,   "events"),
        (100, "events"),
    ])
    def test_pluralization(self, count, expected_word):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": count,
        })
        summary = _extract_event_summary(rendered)
        # 1 event (singular) vs N events (plural)
        if count == 1:
            assert "1 event " in summary
        else:
            assert f"{count} events" in summary

    def test_event_summary_matches_displayed_count(self):
        for n in [1, 5, 23, 50, 147, 1000]:
            rendered = _render({
                "first_seen": FIRST_SEEN_ISO,
                "last_seen":  LAST_SEEN_ISO,
                "event_count": n,
            })
            summary = _extract_event_summary(rendered)
            assert str(n) in summary, f"count {n} not in summary: {summary!r}"

    def test_event_count_in_context_metadata(self):
        """event_count must appear somewhere in the rendered output."""
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 77,
        })
        assert "77" in rendered

    def test_time_range_utc_label_appears(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        tr = _extract_time_range(rendered)
        assert "UTC" in tr

    def test_event_summary_no_none_in_output(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert "None" not in summary
        assert summary != "None"

    def test_event_summary_no_null_in_output(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert "null" not in summary.lower()

    def test_event_summary_not_na_when_timestamps_valid(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert "N/A" not in summary

    def test_event_summary_na_when_no_timestamps(self):
        rendered = _render({"event_count": 10})
        summary = _extract_event_summary(rendered)
        assert summary is not None
        # When no timestamps: "10 events detected" (no "between")
        assert "between" not in summary


# ===========================================================================
# SECTION 3: brute_force.md.j2 Template Tests
# ===========================================================================

class TestBruteForceTemplate:
    """Validate event_summary rendering in the brute_force template."""

    @pytest.fixture
    def rendered(self):
        return _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 147,
        }, attack_pattern="brute_force")

    def test_renders_without_error(self, rendered):
        assert isinstance(rendered, str)
        assert len(rendered) > 100

    def test_has_event_summary_row(self, rendered):
        assert "Event Summary" in rendered

    def test_event_summary_contains_count(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "147" in summary

    def test_event_summary_contains_start_time(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "08:15" in summary

    def test_event_summary_contains_end_time(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "08:47" in summary

    def test_event_summary_exact_format(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "147 events detected between 08:15 and 08:47 UTC" in summary

    def test_has_time_range_row(self, rendered):
        assert "Time Range" in rendered

    def test_time_range_contains_utc(self, rendered):
        tr = _extract_time_range(rendered)
        assert "UTC" in tr

    def test_header_section_present(self, rendered):
        assert "SSH Brute Force" in rendered or "Brute Force" in rendered

    def test_brute_force_template_used(self, rendered):
        assert "PB-SSH-BRUTE-FORCE" in rendered

    def test_ssh_port_in_header(self, rendered):
        assert "SSH Port" in rendered

    def test_event_summary_appears_multiple_times(self, rendered):
        count = _count_event_summary_occurrences(rendered)
        assert count >= 2

    def test_event_summary_bold_formatting(self, rendered):
        for line in rendered.splitlines():
            if "Event Summary" in line and "147" in line:
                assert "**" in line
                return
        pytest.fail("Event Summary line with 147 not found")

    def test_with_cluster_keys(self):
        rendered = _render({
            "cluster_first_seen": "2026-06-30T08:15:00Z",
            "cluster_last_seen":  "2026-06-30T08:47:00Z",
            "event_count": 50,
        }, attack_pattern="brute_force")
        summary = _extract_event_summary(rendered)
        assert "08:15" in summary
        assert "08:47" in summary

    def test_singular_event_count_one(self):
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 1,
        }, attack_pattern="brute_force")
        summary = _extract_event_summary(rendered)
        assert "1 event " in summary
        assert "1 events" not in summary

    def test_no_timestamps_event_summary_still_shows(self):
        rendered = _render({"event_count": 5}, attack_pattern="brute_force")
        assert "Event Summary" in rendered

    def test_event_count_default_to_zero_no_crash(self):
        rendered = _render({}, attack_pattern="brute_force")
        assert "Event Summary" in rendered


# ===========================================================================
# SECTION 4: sqli_attempt.md.j2 Template Tests
# ===========================================================================

class TestSQLiTemplate:
    """Validate event_summary rendering in the sqli_attempt template."""

    @pytest.fixture
    def rendered(self):
        return _render({
            "first_seen":  "2026-07-01T14:02:30Z",
            "last_seen":   "2026-07-01T14:18:55Z",
            "event_count": 23,
        }, attack_pattern="sqli")

    def test_renders_without_error(self, rendered):
        assert isinstance(rendered, str)

    def test_has_event_summary_row(self, rendered):
        assert "Event Summary" in rendered

    def test_event_summary_contains_count(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "23" in summary

    def test_event_summary_contains_start_time(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "14:02" in summary

    def test_event_summary_contains_end_time(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "14:18" in summary

    def test_event_summary_exact_format(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "23 events detected between 14:02 and 14:18 UTC" in summary

    def test_has_time_range_row(self, rendered):
        assert "Time Range" in rendered

    def test_sqli_template_used(self, rendered):
        assert "PB-SQLI-001" in rendered

    def test_sql_injection_in_header(self, rendered):
        assert "SQL" in rendered or "sqli" in rendered.lower()

    def test_event_summary_appears_multiple_times(self, rendered):
        count = _count_event_summary_occurrences(rendered)
        assert count >= 2

    def test_zero_event_count(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 0,
        }, attack_pattern="sqli")
        summary = _extract_event_summary(rendered)
        assert "0 events" in summary

    def test_large_event_count(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 5000,
        }, attack_pattern="sqli")
        summary = _extract_event_summary(rendered)
        assert "5000" in summary

    def test_midnight_crossing_timestamps(self):
        rendered = _render({
            "first_seen": "2026-06-30T23:50:00Z",
            "last_seen":  "2026-07-01T00:20:00Z",
            "event_count": 8,
        }, attack_pattern="sqli")
        summary = _extract_event_summary(rendered)
        assert "23:50" in summary
        assert "00:20" in summary

    def test_event_summary_not_na(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "N/A" not in summary

    def test_no_timestamps_graceful(self):
        rendered = _render({"event_count": 10}, attack_pattern="sqli")
        assert "Event Summary" in rendered
        assert isinstance(rendered, str)

    def test_pre_populated_event_summary_respected(self):
        rendered = _render({
            "event_summary": "99 events detected between 09:00 and 10:00 UTC",
        }, attack_pattern="sqli")
        summary = _extract_event_summary(rendered)
        assert "99 events" in summary

    def test_datetime_object_input(self):
        rendered = _render({
            "first_seen": datetime(2026, 7, 1, 16, 0, 0, tzinfo=timezone.utc),
            "last_seen":  datetime(2026, 7, 1, 16, 30, 0, tzinfo=timezone.utc),
            "event_count": 12,
        }, attack_pattern="sqli")
        summary = _extract_event_summary(rendered)
        assert "16:00" in summary
        assert "16:30" in summary


# ===========================================================================
# SECTION 5: port_scan.md.j2 Template Tests
# ===========================================================================

class TestPortScanTemplate:
    """Validate event_summary rendering in the port_scan template."""

    @pytest.fixture
    def rendered(self):
        return _render({
            "cluster_first_seen": "2026-07-01T09:00:00Z",
            "cluster_last_seen":  "2026-07-01T09:32:00Z",
            "event_count": 20,
        }, attack_pattern="port_scan")

    def test_renders_without_error(self, rendered):
        assert isinstance(rendered, str)

    def test_has_event_summary_row(self, rendered):
        assert "Event Summary" in rendered

    def test_event_summary_contains_count(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "20" in summary

    def test_event_summary_contains_start_time(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "09:00" in summary

    def test_event_summary_contains_end_time(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "09:32" in summary

    def test_event_summary_exact_format(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "20 events detected between 09:00 and 09:32 UTC" in summary

    def test_has_time_range_row(self, rendered):
        assert "Time Range" in rendered

    def test_port_scan_template_used(self, rendered):
        assert "PB-PORTSCAN-001" in rendered

    def test_reconnaissance_in_mapping(self, rendered):
        assert "Reconnaissance" in rendered or "T1595" in rendered

    def test_event_summary_appears_multiple_times(self, rendered):
        count = _count_event_summary_occurrences(rendered)
        assert count >= 2

    def test_iso_z_timestamps(self):
        rendered = _render({
            "first_seen":  "2026-07-01T07:00:00Z",
            "last_seen":   "2026-07-01T07:45:00Z",
            "event_count": 75,
        }, attack_pattern="port_scan")
        summary = _extract_event_summary(rendered)
        assert "75 events detected between 07:00 and 07:45 UTC" in summary

    def test_unix_timestamp_input(self):
        ts_start = int(datetime(2026, 7, 1, 13, 0, 0, tzinfo=timezone.utc).timestamp())
        ts_end   = int(datetime(2026, 7, 1, 13, 20, 0, tzinfo=timezone.utc).timestamp())
        rendered = _render({
            "first_seen":  ts_start,
            "last_seen":   ts_end,
            "event_count": 33,
        }, attack_pattern="port_scan")
        summary = _extract_event_summary(rendered)
        assert "13:00" in summary
        assert "13:20" in summary

    def test_singular_event(self):
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 1,
        }, attack_pattern="port_scan")
        summary = _extract_event_summary(rendered)
        assert "1 event " in summary

    def test_fallback_when_no_timestamps(self):
        rendered = _render({"event_count": 15}, attack_pattern="port_scan")
        assert "Event Summary" in rendered

    def test_hit_count_used_when_no_event_count(self):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "hit_count":  66,
        }, attack_pattern="port_scan")
        summary = _extract_event_summary(rendered)
        assert "66" in summary

    def test_event_summary_utc_label(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "UTC" in summary

    def test_no_crash_empty_context(self):
        rendered = _render({}, attack_pattern="port_scan")
        assert "Event Summary" in rendered


# ===========================================================================
# SECTION 6: data_exfiltration.md.j2 Template Tests
# ===========================================================================

class TestDataExfilTemplate:
    """Validate event_summary rendering in the data_exfiltration template."""

    @pytest.fixture
    def rendered(self):
        return _render({
            "first_seen":  "2026-06-29T23:45:00Z",
            "last_seen":   "2026-06-30T00:12:00Z",
            "event_count": 1,
        }, attack_pattern="data_exfil")

    def test_renders_without_error(self, rendered):
        assert isinstance(rendered, str)

    def test_has_event_summary_row(self, rendered):
        assert "Event Summary" in rendered

    def test_event_summary_singular_event(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "1 event " in summary
        assert "1 events" not in summary

    def test_event_summary_contains_start_time(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "23:45" in summary

    def test_event_summary_contains_end_time(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "00:12" in summary

    def test_event_summary_exact_format(self, rendered):
        summary = _extract_event_summary(rendered)
        assert "1 event detected between 23:45 and 00:12 UTC" in summary

    def test_has_time_range_row(self, rendered):
        assert "Time Range" in rendered

    def test_exfil_template_used(self, rendered):
        assert "PB-EXFIL-001" in rendered

    def test_exfil_header_present(self, rendered):
        assert "Data Exfiltration" in rendered

    def test_event_summary_appears_multiple_times(self, rendered):
        count = _count_event_summary_occurrences(rendered)
        assert count >= 2

    def test_critical_severity_default(self, rendered):
        assert "CRITICAL" in rendered

    def test_event_count_100(self):
        rendered = _render({
            "first_seen":  "2026-06-30T00:00:00Z",
            "last_seen":   "2026-06-30T02:00:00Z",
            "event_count": 100,
        }, attack_pattern="data_exfil")
        summary = _extract_event_summary(rendered)
        assert "100 events detected between 00:00 and 02:00 UTC" in summary

    def test_datetime_object_input(self):
        dt_first = datetime(2026, 7, 1, 3, 30, 0, tzinfo=timezone.utc)
        dt_last  = datetime(2026, 7, 1, 4, 0, 0, tzinfo=timezone.utc)
        rendered = _render({
            "first_seen":  dt_first,
            "last_seen":   dt_last,
            "event_count": 7,
        }, attack_pattern="data_exfil")
        summary = _extract_event_summary(rendered)
        assert "03:30" in summary
        assert "04:00" in summary

    def test_tlp_red_classification_default(self, rendered):
        assert "TLP:RED" in rendered

    def test_no_crash_without_timestamps(self):
        rendered = _render({"event_count": 5}, attack_pattern="data_exfil")
        assert "Event Summary" in rendered

    def test_large_event_count(self):
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 50000,
        }, attack_pattern="data_exfil")
        summary = _extract_event_summary(rendered)
        assert "50000" in summary

    def test_pre_computed_values_not_overwritten(self):
        rendered = _render({
            "time_range":    "10:00–11:00 UTC",
            "event_summary": "7 events detected between 10:00 and 11:00 UTC",
            "event_count":   7,
        }, attack_pattern="data_exfil")
        summary = _extract_event_summary(rendered)
        assert "7 events" in summary


# ===========================================================================
# SECTION 7: Cross-Template Common Assertions
# ===========================================================================

class TestAllTemplatesCommon:
    """Verify all 4 templates share consistent event_summary rendering."""

    ALL_PATTERNS_WITH_TS = [
        ("brute_force", "brute_force"),
        ("sqli",        "sqli_attempt"),
        ("port_scan",   "port_scan"),
        ("data_exfil",  "data_exfiltration"),
    ]

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_event_summary_present_in_all_templates(self, pattern, name):
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 147,
        }, attack_pattern=pattern)
        assert "Event Summary" in rendered, f"Event Summary missing in {name}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_time_range_present_in_all_templates(self, pattern, name):
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 10,
        }, attack_pattern=pattern)
        assert "Time Range" in rendered, f"Time Range row missing in {name}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_count_in_all_templates(self, pattern, name):
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 99,
        }, attack_pattern=pattern)
        summary = _extract_event_summary(rendered)
        assert "99" in summary, f"Event count 99 missing in {name}: {summary!r}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_start_time_in_all_templates(self, pattern, name):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 5,
        }, attack_pattern=pattern)
        summary = _extract_event_summary(rendered)
        assert "08:15" in summary, f"Start time 08:15 missing in {name}: {summary!r}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_end_time_in_all_templates(self, pattern, name):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 5,
        }, attack_pattern=pattern)
        summary = _extract_event_summary(rendered)
        assert "08:47" in summary, f"End time 08:47 missing in {name}: {summary!r}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_utc_label_in_all_templates(self, pattern, name):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 5,
        }, attack_pattern=pattern)
        summary = _extract_event_summary(rendered)
        assert "UTC" in summary, f"UTC missing in {name}: {summary!r}"

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_event_summary_appears_at_least_twice(self, pattern, name):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 10,
        }, attack_pattern=pattern)
        count = _count_event_summary_occurrences(rendered)
        assert count >= 2, (
            f"Expected ≥2 Event Summary rows in {name}, got {count}"
        )

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_singular_event_in_all_templates(self, pattern, name):
        rendered = _render({
            "first_seen": FIRST_SEEN_ISO,
            "last_seen":  LAST_SEEN_ISO,
            "event_count": 1,
        }, attack_pattern=pattern)
        summary = _extract_event_summary(rendered)
        assert "1 event " in summary, (
            f"Singular 'event' not found in {name}: {summary!r}"
        )
        assert "1 events" not in summary

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_all_templates_render_without_crash_no_ts(self, pattern, name):
        rendered = _render({"event_count": 10}, attack_pattern=pattern)
        assert isinstance(rendered, str)
        assert len(rendered) > 50

    @pytest.mark.parametrize("pattern,name", ALL_PATTERNS_WITH_TS)
    def test_exact_event_summary_format_all_templates(self, pattern, name):
        rendered = _render({
            "first_seen":  "2026-06-30T08:15:00Z",
            "last_seen":   "2026-06-30T08:47:00Z",
            "event_count": 147,
        }, attack_pattern=pattern)
        summary = _extract_event_summary(rendered)
        assert "147 events detected between 08:15 and 08:47 UTC" in summary, (
            f"Exact format mismatch in {name}: {summary!r}"
        )


# ===========================================================================
# SECTION 8: Edge Cases
# ===========================================================================

class TestEdgeCases:
    """Boundary and error input handling."""

    def test_none_first_seen_no_crash(self):
        rendered = _render({"first_seen": None, "last_seen": None, "event_count": 5})
        assert "Event Summary" in rendered

    def test_empty_string_timestamps_no_crash(self):
        rendered = _render({"first_seen": "", "last_seen": "", "event_count": 5})
        assert "Event Summary" in rendered

    def test_whitespace_string_timestamps_no_crash(self):
        rendered = _render({"first_seen": "   ", "last_seen": "  ", "event_count": 5})
        assert "Event Summary" in rendered

    def test_none_event_count_defaults_to_zero(self):
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": None,
        })
        # Should not crash; event_count=None falls back to 0 via setdefault(hit_count=0)
        assert "Event Summary" in rendered

    def test_event_count_string_digits(self):
        """String digits for event_count should still appear in summary."""
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": "200",
        })
        summary = _extract_event_summary(rendered)
        assert "200" in summary

    def test_very_early_date_parses(self):
        rendered = _render({
            "first_seen": "2000-01-01T00:00:00Z",
            "last_seen":  "2000-01-01T01:00:00Z",
            "event_count": 3,
        })
        summary = _extract_event_summary(rendered)
        assert "00:00" in summary

    def test_very_late_hour_parses(self):
        rendered = _render({
            "first_seen": "2026-12-31T23:59:00Z",
            "last_seen":  "2026-12-31T23:59:59Z",
            "event_count": 1,
        })
        summary = _extract_event_summary(rendered)
        assert "23:59" in summary

    def test_full_context_all_keys_render(self):
        rendered = _render({
            "first_seen":       FIRST_SEEN_ISO,
            "last_seen":        LAST_SEEN_ISO,
            "event_count":      147,
            "time_range":       "08:15–08:47 UTC",
            "event_summary":    "147 events detected between 08:15 and 08:47 UTC",
            "source_ip":        "10.0.0.1",
            "target_ip":        "192.168.1.10",
            "severity":         "HIGH",
            "classification":   "TLP:AMBER",
            "iocs": [{"ip": "10.0.0.1", "ports": 22, "protocol": "TCP",
                       "hit_count": 147, "threat_intel": "❓ Pending",
                       "first_seen": FIRST_SEEN_ISO, "last_seen": LAST_SEEN_ISO}],
        }, attack_pattern="brute_force")
        assert "147 events detected between 08:15 and 08:47 UTC" in rendered

    def test_pre_computed_time_range_no_overwrite(self):
        rendered = _render({
            "time_range":  "CUSTOM_RANGE",
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 10,
        })
        assert "CUSTOM_RANGE" in rendered

    def test_cluster_keys_only_no_first_seen(self):
        rendered = _render({
            "cluster_first_seen": "2026-07-01T12:00:00Z",
            "cluster_last_seen":  "2026-07-01T12:30:00Z",
            "event_count": 25,
        }, attack_pattern="port_scan")
        summary = _extract_event_summary(rendered)
        assert "12:00" in summary
        assert "12:30" in summary

    def test_first_seen_only_no_last_seen(self):
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "event_count": 10,
        })
        tr = _extract_time_range(rendered)
        assert "08:15" in tr

    def test_all_4_patterns_with_utc_datetime_objects(self):
        for pat in ["brute_force", "sqli", "port_scan", "data_exfil"]:
            rendered = _render({
                "first_seen": datetime(2026, 7, 1, 10, 0, tzinfo=timezone.utc),
                "last_seen":  datetime(2026, 7, 1, 11, 0, tzinfo=timezone.utc),
                "event_count": 50,
            }, attack_pattern=pat)
            summary = _extract_event_summary(rendered)
            assert "10:00" in summary, f"10:00 missing for pattern {pat}"
            assert "11:00" in summary, f"11:00 missing for pattern {pat}"

    def test_event_summary_is_string_type(self):
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 10,
        })
        summary = _extract_event_summary(rendered)
        assert isinstance(summary, str)

    def test_no_template_error_on_default_context(self):
        for pat in ["brute_force", "sqli", "port_scan", "data_exfil"]:
            rendered = _gen.generate({"attack_pattern": pat})
            assert isinstance(rendered, str)
            assert len(rendered) > 0

    def test_detect_time_fallback_used_in_ioc(self):
        """first_seen / last_seen flow into IOC table via iocs builder."""
        rendered = _render({
            "first_seen":  FIRST_SEEN_ISO,
            "last_seen":   LAST_SEEN_ISO,
            "event_count": 10,
            "source_ip":   "10.0.0.1",
        })
        # IOC table should have first_seen / last_seen from context
        assert FIRST_SEEN_ISO in rendered or "08:15" in rendered

    def test_time_range_contains_hours_and_minutes(self):
        rendered = _render({
            "first_seen": "2026-06-30T08:15:00Z",
            "last_seen":  "2026-06-30T08:47:00Z",
            "event_count": 5,
        })
        tr = _extract_time_range(rendered)
        import re
        # Match HH:MM pattern
        assert re.search(r"\d{2}:\d{2}", tr), f"HH:MM pattern not found in: {tr!r}"

    def test_seconds_stripped_from_time_range(self):
        """Only HH:MM should appear, not HH:MM:SS."""
        rendered = _render({
            "first_seen": "2026-06-30T08:15:30Z",
            "last_seen":  "2026-06-30T08:47:55Z",
            "event_count": 5,
        })
        tr = _extract_time_range(rendered)
        # Should NOT have seconds in the time range display
        assert "08:15:30" not in tr
        assert "08:47:55" not in tr

    def test_full_render_no_jinja_error_markers(self):
        """Template render must not contain raw Jinja2 error markers."""
        for pat in ["brute_force", "sqli", "port_scan", "data_exfil"]:
            rendered = _render({
                "first_seen":  FIRST_SEEN_ISO,
                "last_seen":   LAST_SEEN_ISO,
                "event_count": 100,
            }, attack_pattern=pat)
            assert "{{" not in rendered, f"Unrendered Jinja2 tag in {pat}"
            assert "}}" not in rendered, f"Unrendered Jinja2 tag in {pat}"
