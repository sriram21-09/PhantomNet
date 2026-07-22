"""
backend/tests/test_mitre_matrix_endpoint.py
-------------------------------------------
Unit tests for GET /api/sentinel/mitre/matrix

Covers:
  sentinel/mitre_matrix._base_technique_id()   (6 cases)
  sentinel/mitre_matrix.get_mitre_matrix_config()  (6 cases)
  sentinel/mitre_matrix.get_playbook_counts_by_technique()  (3 cases)
  sentinel/mitre_matrix.build_matrix_response()   (13 cases)

Week 18, Day 3 - MITRE ATT&CK Matrix endpoint tests
"""

from __future__ import annotations

import re
import sys
import os
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Ensure backend/ is importable
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _make_mock_db(results):
    """Return a mock SQLAlchemy session whose chained query returns `results`."""
    mock_db = MagicMock()
    mock_q = MagicMock()
    mock_db.query.return_value = mock_q
    mock_q.filter.return_value = mock_q
    mock_q.group_by.return_value = mock_q
    mock_q.all.return_value = results
    return mock_db


# ===========================================================================
# 1. _base_technique_id()
# ===========================================================================

class TestBaseTechniqueId:
    """Tests for the internal _base_technique_id() helper."""

    def test_strips_sub_technique_001(self):
        from sentinel.mitre_matrix import _base_technique_id
        assert _base_technique_id("T1110.001") == "T1110"

    def test_strips_sub_technique_007(self):
        from sentinel.mitre_matrix import _base_technique_id
        assert _base_technique_id("T1059.007") == "T1059"

    def test_base_id_t1046_unchanged(self):
        from sentinel.mitre_matrix import _base_technique_id
        assert _base_technique_id("T1046") == "T1046"

    def test_base_id_t1190_unchanged(self):
        from sentinel.mitre_matrix import _base_technique_id
        assert _base_technique_id("T1190") == "T1190"

    def test_empty_string_returns_empty(self):
        from sentinel.mitre_matrix import _base_technique_id
        assert _base_technique_id("") == ""

    def test_none_returns_none(self):
        from sentinel.mitre_matrix import _base_technique_id
        assert _base_technique_id(None) is None


# ===========================================================================
# 2. get_mitre_matrix_config()
# ===========================================================================

class TestGetMitreMatrixConfig:
    """Tests for get_mitre_matrix_config()."""

    def test_returns_dict(self):
        from sentinel.mitre_matrix import get_mitre_matrix_config
        assert isinstance(get_mitre_matrix_config(), dict)

    def test_non_empty(self):
        from sentinel.mitre_matrix import get_mitre_matrix_config
        assert len(get_mitre_matrix_config()) > 0

    def test_known_tactics_present(self):
        from sentinel.mitre_matrix import get_mitre_matrix_config
        config = get_mitre_matrix_config()
        expected = {
            "Credential Access", "Lateral Movement", "Initial Access",
            "Execution", "Discovery", "Exfiltration",
            "Command and Control", "Reconnaissance", "Impact",
        }
        for tactic in expected:
            assert tactic in config, f"Tactic '{tactic}' missing from matrix config"

    def test_technique_objects_have_required_fields(self):
        from sentinel.mitre_matrix import get_mitre_matrix_config
        required = {"technique_id", "technique_name", "tactic_id", "severity", "url", "description"}
        for tactic, techs in get_mitre_matrix_config().items():
            for tech in techs:
                missing = required - set(tech.keys())
                assert not missing, f"Technique in '{tactic}' missing fields: {missing}"

    def test_no_duplicate_technique_ids_per_tactic(self):
        """T1046 is referenced by two signatures but must appear only once."""
        from sentinel.mitre_matrix import get_mitre_matrix_config
        for tactic, techs in get_mitre_matrix_config().items():
            ids = [t["technique_id"] for t in techs]
            assert len(ids) == len(set(ids)), f"Duplicate IDs in tactic '{tactic}': {ids}"

    def test_each_tactic_entry_is_a_list(self):
        from sentinel.mitre_matrix import get_mitre_matrix_config
        for tactic, techs in get_mitre_matrix_config().items():
            assert isinstance(techs, list), f"Expected list for '{tactic}'"


# ===========================================================================
# 3. get_playbook_counts_by_technique()
# ===========================================================================

class TestGetPlaybookCountsByTechnique:
    """Tests for get_playbook_counts_by_technique() with a mocked DB."""

    def test_returns_dict(self):
        from sentinel.mitre_matrix import get_playbook_counts_by_technique
        result = get_playbook_counts_by_technique(_make_mock_db([("T1110.001", 5)]))
        assert isinstance(result, dict)

    def test_correct_counts(self):
        from sentinel.mitre_matrix import get_playbook_counts_by_technique
        counts = get_playbook_counts_by_technique(
            _make_mock_db([("T1110.001", 5), ("T1046", 3)])
        )
        assert counts["T1110.001"] == 5
        assert counts["T1046"] == 3

    def test_empty_db_returns_empty_dict(self):
        from sentinel.mitre_matrix import get_playbook_counts_by_technique
        assert get_playbook_counts_by_technique(_make_mock_db([])) == {}


# ===========================================================================
# 4. build_matrix_response()
# ===========================================================================

class TestBuildMatrixResponse:
    """Tests for build_matrix_response() - the canonical API response builder."""

    def test_required_top_level_keys(self):
        from sentinel.mitre_matrix import build_matrix_response
        resp = build_matrix_response(_make_mock_db([]))
        required = {"status", "generated_at", "total_tactics", "total_techniques", "matrix", "frequency_map"}
        assert required == set(resp.keys()), f"Keys mismatch. Got: {set(resp.keys())}"

    def test_status_is_success(self):
        from sentinel.mitre_matrix import build_matrix_response
        assert build_matrix_response(_make_mock_db([]))["status"] == "success"

    def test_generated_at_is_iso8601(self):
        from sentinel.mitre_matrix import build_matrix_response
        ts = build_matrix_response(_make_mock_db([]))["generated_at"]
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts), \
            f"generated_at not ISO-8601: {ts}"

    def test_total_tactics_is_positive_int(self):
        from sentinel.mitre_matrix import build_matrix_response
        resp = build_matrix_response(_make_mock_db([]))
        assert isinstance(resp["total_tactics"], int) and resp["total_tactics"] > 0

    def test_total_techniques_is_positive_int(self):
        from sentinel.mitre_matrix import build_matrix_response
        resp = build_matrix_response(_make_mock_db([]))
        assert isinstance(resp["total_techniques"], int) and resp["total_techniques"] > 0

    def test_matrix_is_dict(self):
        from sentinel.mitre_matrix import build_matrix_response
        assert isinstance(build_matrix_response(_make_mock_db([]))["matrix"], dict)

    def test_frequency_map_is_dict(self):
        from sentinel.mitre_matrix import build_matrix_response
        assert isinstance(build_matrix_response(_make_mock_db([]))["frequency_map"], dict)

    def test_frequency_map_keys_have_no_sub_technique_suffix(self):
        """All frequency_map keys must be base IDs (no dots)."""
        from sentinel.mitre_matrix import build_matrix_response
        freq = build_matrix_response(
            _make_mock_db([("T1110.001", 4), ("T1110.004", 2)])
        )["frequency_map"]
        for key in freq:
            assert "." not in key, f"frequency_map key '{key}' has sub-technique suffix"

    def test_frequency_map_aggregates_sub_techniques(self):
        """T1110.001 (4) + T1110.004 (2) must aggregate to T1110 = 6."""
        from sentinel.mitre_matrix import build_matrix_response
        freq = build_matrix_response(
            _make_mock_db([("T1110.001", 4), ("T1110.004", 2)])
        )["frequency_map"]
        assert freq.get("T1110", 0) == 6

    def test_zero_counts_when_no_playbooks(self):
        """With empty DB every technique count must be 0."""
        from sentinel.mitre_matrix import build_matrix_response
        resp = build_matrix_response(_make_mock_db([]))
        for tactic, techs in resp["matrix"].items():
            for tech in techs:
                assert tech["count"] == 0, \
                    f"Expected count=0 for {tech['technique_id']} in {tactic}, got {tech['count']}"

    def test_technique_count_populated_from_db(self):
        """T1046 with 7 DB records must appear with count=7 in Discovery."""
        from sentinel.mitre_matrix import build_matrix_response
        resp = build_matrix_response(_make_mock_db([("T1046", 7)]))
        discovery = resp["matrix"].get("Discovery", [])
        t1046 = next((t for t in discovery if t["technique_id"] == "T1046"), None)
        assert t1046 is not None, "T1046 must be in Discovery tactic"
        assert t1046["count"] == 7

    def test_count_field_present_on_all_techniques(self):
        from sentinel.mitre_matrix import build_matrix_response
        resp = build_matrix_response(_make_mock_db([]))
        for tactic, techs in resp["matrix"].items():
            for tech in techs:
                assert "count" in tech, \
                    f"{tech.get('technique_id')} in {tactic} missing 'count'"

    def test_total_techniques_matches_matrix_sum(self):
        from sentinel.mitre_matrix import build_matrix_response
        resp = build_matrix_response(_make_mock_db([]))
        counted = sum(len(v) for v in resp["matrix"].values())
        assert resp["total_techniques"] == counted

    def test_total_tactics_matches_matrix_key_count(self):
        from sentinel.mitre_matrix import build_matrix_response
        resp = build_matrix_response(_make_mock_db([]))
        assert resp["total_tactics"] == len(resp["matrix"])
