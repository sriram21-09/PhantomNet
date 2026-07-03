"""
tests/test_confidence_scoring.py
---------------------------------
Comprehensive unit tests for backend/sentinel/confidence_scoring.py

Coverage
--------
1. TestConfidenceToSeverity        — boundary mapping: CRITICAL/HIGH/MEDIUM/LOW
2. TestNormaliseClusterSize        — linear normalisation + cap + edge cases
3. TestNormaliseMLScores           — averaging, 0–100 scale, empty/None handling
4. TestCalculateIOCDensity         — ratio, cap, zero-division guard
5. TestMultiProtoBonus             — single vs. multi-protocol detection
6. TestCalculateConfidence         — full weighted formula, all scenarios
7. TestCalculateConfidenceWeights  — custom weight validation
8. TestConfidenceResultNamedTuple  — NamedTuple field completeness
9. TestSeverityThresholdEdgeCases  — exact boundary values
10. TestScenarioBasedScoring       — real-world attack cluster scenarios
"""

from __future__ import annotations

import math
import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "backend")
for _p in (_ROOT, _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from sentinel.confidence_scoring import (
    DEFAULT_WEIGHTS,
    ConfidenceResult,
    _calculate_ioc_density,
    _multi_proto_bonus,
    _normalise_cluster_size,
    _normalise_ml_scores,
    calculate_confidence,
    confidence_to_severity,
)


# ===========================================================================
# 1. CONFIDENCE TO SEVERITY MAPPING
# ===========================================================================

class TestConfidenceToSeverity:
    """Verify the four severity tier mappings and boundary conditions."""

    # ── CRITICAL tier ──────────────────────────────────────────────────────
    def test_critical_at_exactly_0_80(self):
        assert confidence_to_severity(0.80) == "CRITICAL"

    def test_critical_above_0_80(self):
        assert confidence_to_severity(0.85) == "CRITICAL"

    def test_critical_at_1_0(self):
        assert confidence_to_severity(1.0) == "CRITICAL"

    def test_critical_above_1_0_clamped(self):
        # Values above 1.0 are clamped; still CRITICAL
        assert confidence_to_severity(1.5) == "CRITICAL"

    def test_critical_at_0_999(self):
        assert confidence_to_severity(0.999) == "CRITICAL"

    # ── HIGH tier ───────────────────────────────────────────────────────────
    def test_high_at_exactly_0_60(self):
        assert confidence_to_severity(0.60) == "HIGH"

    def test_high_at_0_79(self):
        assert confidence_to_severity(0.79) == "HIGH"

    def test_high_at_0_70(self):
        assert confidence_to_severity(0.70) == "HIGH"

    def test_not_critical_at_0_799(self):
        assert confidence_to_severity(0.799) == "HIGH"

    # ── MEDIUM tier ─────────────────────────────────────────────────────────
    def test_medium_at_exactly_0_40(self):
        assert confidence_to_severity(0.40) == "MEDIUM"

    def test_medium_at_0_59(self):
        assert confidence_to_severity(0.59) == "MEDIUM"

    def test_medium_at_0_50(self):
        assert confidence_to_severity(0.50) == "MEDIUM"

    def test_not_high_at_0_599(self):
        assert confidence_to_severity(0.599) == "MEDIUM"

    # ── LOW tier ────────────────────────────────────────────────────────────
    def test_low_at_exactly_0_0(self):
        assert confidence_to_severity(0.0) == "LOW"

    def test_low_at_0_39(self):
        assert confidence_to_severity(0.39) == "LOW"

    def test_low_at_0_20(self):
        assert confidence_to_severity(0.20) == "LOW"

    def test_low_negative_clamped(self):
        assert confidence_to_severity(-0.5) == "LOW"

    def test_not_medium_at_0_399(self):
        assert confidence_to_severity(0.399) == "LOW"

    # ── Return type ─────────────────────────────────────────────────────────
    def test_returns_string(self):
        assert isinstance(confidence_to_severity(0.7), str)

    def test_all_valid_return_values(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for val in [0.0, 0.2, 0.39, 0.4, 0.5, 0.59, 0.6, 0.7, 0.79, 0.8, 0.9, 1.0]:
            assert confidence_to_severity(val) in valid


# ===========================================================================
# 2. NORMALISE CLUSTER SIZE
# ===========================================================================

class TestNormaliseClusterSize:
    """Verify linear normalisation of event count to [0.0, 1.0]."""

    def test_zero_events_returns_zero(self):
        assert _normalise_cluster_size(0) == 0.0

    def test_negative_events_returns_zero(self):
        assert _normalise_cluster_size(-10) == 0.0

    def test_half_cap_returns_half(self):
        assert _normalise_cluster_size(100, cap=200) == 0.5

    def test_at_cap_returns_one(self):
        assert _normalise_cluster_size(200, cap=200) == 1.0

    def test_above_cap_clamped_to_one(self):
        assert _normalise_cluster_size(999, cap=200) == 1.0

    def test_single_event_small_cap(self):
        result = _normalise_cluster_size(1, cap=10)
        assert result == pytest.approx(0.1, abs=1e-9)

    def test_default_cap_is_200(self):
        # 100 events with default cap of 200
        result = _normalise_cluster_size(100)
        assert result == pytest.approx(0.5, abs=1e-9)

    def test_custom_cap(self):
        result = _normalise_cluster_size(50, cap=100)
        assert result == pytest.approx(0.5, abs=1e-9)

    def test_zero_cap_uses_fallback(self):
        # cap=0 is invalid; implementation must not divide by zero
        result = _normalise_cluster_size(100, cap=0)
        assert 0.0 <= result <= 1.0

    def test_result_always_in_range(self):
        for count in [0, 1, 50, 100, 200, 500, 10000]:
            result = _normalise_cluster_size(count)
            assert 0.0 <= result <= 1.0


# ===========================================================================
# 3. NORMALISE ML SCORES
# ===========================================================================

class TestNormaliseMLScores:
    """Verify ML score averaging and 0–100 → 0.0–1.0 normalisation."""

    def test_empty_list_returns_zero(self):
        assert _normalise_ml_scores([]) == 0.0

    def test_single_score_50(self):
        assert _normalise_ml_scores([50.0]) == pytest.approx(0.5, abs=1e-6)

    def test_single_score_100(self):
        assert _normalise_ml_scores([100.0]) == pytest.approx(1.0, abs=1e-6)

    def test_single_score_0(self):
        assert _normalise_ml_scores([0.0]) == pytest.approx(0.0, abs=1e-6)

    def test_average_two_scores(self):
        # (80 + 100) / 2 = 90 → 0.9
        assert _normalise_ml_scores([80.0, 100.0]) == pytest.approx(0.9, abs=1e-5)

    def test_average_three_scores(self):
        # (60 + 70 + 80) / 3 = 70 → 0.7
        assert _normalise_ml_scores([60.0, 70.0, 80.0]) == pytest.approx(0.7, abs=1e-5)

    def test_all_zeros_returns_zero(self):
        assert _normalise_ml_scores([0.0, 0.0, 0.0]) == 0.0

    def test_scores_above_100_clamped(self):
        # 150 → clamped to 100 → score 1.0
        result = _normalise_ml_scores([150.0])
        assert result == pytest.approx(1.0, abs=1e-6)

    def test_negative_scores_clamped_to_zero(self):
        result = _normalise_ml_scores([-50.0])
        assert result == pytest.approx(0.0, abs=1e-6)

    def test_none_values_skipped(self):
        # None values should be ignored; average of [80.0] = 0.8
        result = _normalise_ml_scores([None, 80.0, None])
        assert result == pytest.approx(0.8, abs=1e-6)

    def test_all_none_returns_zero(self):
        result = _normalise_ml_scores([None, None])
        assert result == 0.0

    def test_result_always_in_range(self):
        for scores in [[], [0], [50], [100], [0, 100], [25, 75, 50]]:
            result = _normalise_ml_scores(scores)
            assert 0.0 <= result <= 1.0


# ===========================================================================
# 4. IOC DENSITY
# ===========================================================================

class TestCalculateIOCDensity:
    """Verify IOC density ratio calculation."""

    def test_zero_events_returns_zero(self):
        assert _calculate_ioc_density(5, 0) == 0.0

    def test_zero_iocs_returns_zero(self):
        assert _calculate_ioc_density(0, 10) == 0.0

    def test_half_density(self):
        assert _calculate_ioc_density(5, 10) == pytest.approx(0.5, abs=1e-9)

    def test_full_density(self):
        assert _calculate_ioc_density(10, 10) == pytest.approx(1.0, abs=1e-9)

    def test_more_iocs_than_events_capped_at_one(self):
        assert _calculate_ioc_density(15, 10) == pytest.approx(1.0, abs=1e-9)

    def test_one_ioc_one_event(self):
        assert _calculate_ioc_density(1, 1) == pytest.approx(1.0, abs=1e-9)

    def test_one_ioc_many_events(self):
        assert _calculate_ioc_density(1, 100) == pytest.approx(0.01, abs=1e-9)

    def test_result_always_in_range(self):
        for iocs, events in [(0, 10), (5, 10), (10, 10), (20, 10), (0, 0)]:
            result = _calculate_ioc_density(iocs, events)
            assert 0.0 <= result <= 1.0

    def test_negative_ioc_count_returns_zero(self):
        result = _calculate_ioc_density(-1, 10)
        assert result == 0.0

    def test_negative_event_count_returns_zero(self):
        result = _calculate_ioc_density(5, -10)
        assert result == 0.0


# ===========================================================================
# 5. MULTI-PROTOCOL BONUS
# ===========================================================================

class TestMultiProtoBonus:
    """Verify multi-protocol detection logic."""

    def test_empty_protocols_returns_zero(self):
        assert _multi_proto_bonus([]) == 0.0

    def test_single_protocol_returns_zero(self):
        assert _multi_proto_bonus(["TCP"]) == 0.0

    def test_two_same_protocols_returns_zero(self):
        assert _multi_proto_bonus(["TCP", "TCP"]) == 0.0

    def test_two_different_protocols_returns_one(self):
        assert _multi_proto_bonus(["TCP", "UDP"]) == 1.0

    def test_three_protocols_with_duplicate_returns_one(self):
        assert _multi_proto_bonus(["TCP", "TCP", "UDP"]) == 1.0

    def test_icmp_plus_tcp_returns_one(self):
        assert _multi_proto_bonus(["TCP", "ICMP"]) == 1.0

    def test_case_insensitive(self):
        assert _multi_proto_bonus(["tcp", "UDP"]) == 1.0

    def test_returns_float(self):
        result = _multi_proto_bonus(["TCP", "UDP"])
        assert isinstance(result, float)

    def test_whitespace_stripped(self):
        # Extra whitespace should be stripped
        result = _multi_proto_bonus(["  TCP  ", "UDP"])
        assert result == 1.0

    def test_none_entries_filtered(self):
        # None protocol strings should be ignored
        result = _multi_proto_bonus([None, "TCP"])
        assert result == 0.0

    def test_empty_string_entries_filtered(self):
        result = _multi_proto_bonus(["", "TCP"])
        assert result == 0.0


# ===========================================================================
# 6. CALCULATE CONFIDENCE — FULL FORMULA
# ===========================================================================

class TestCalculateConfidence:
    """Verify the weighted average formula and ConfidenceResult contents."""

    def test_returns_confidence_result(self):
        result = calculate_confidence(100, [50.0], 5, ["TCP"])
        assert isinstance(result, ConfidenceResult)

    def test_confidence_in_range(self):
        result = calculate_confidence(100, [50.0], 5, ["TCP"])
        assert 0.0 <= result.confidence <= 1.0

    def test_severity_is_valid_tier(self):
        result = calculate_confidence(100, [50.0], 5, ["TCP"])
        assert result.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_all_max_inputs_gives_high_confidence(self):
        """Max cluster + max ML + full IOC density + multi-proto → near 1.0."""
        result = calculate_confidence(
            event_count=200,
            ml_scores=[100.0] * 10,
            unique_ioc_count=200,
            protocols=["TCP", "UDP"],
        )
        assert result.confidence > 0.85
        assert result.severity == "CRITICAL"

    def test_all_zero_inputs_gives_zero_confidence(self):
        result = calculate_confidence(
            event_count=0,
            ml_scores=[],
            unique_ioc_count=0,
            protocols=[],
        )
        assert result.confidence == 0.0
        assert result.severity == "LOW"

    def test_only_cluster_size_contributes(self):
        """With ml_scores empty, ioc=0, single proto, only cluster_size contributes."""
        result = calculate_confidence(
            event_count=200,       # cluster_size_score = 1.0
            ml_scores=[],          # ml_avg_score = 0.0
            unique_ioc_count=0,    # ioc_density = 0.0
            protocols=["TCP"],     # multi_proto_bonus = 0.0
        )
        expected = DEFAULT_WEIGHTS["cluster_size"] * 1.0
        assert result.confidence == pytest.approx(expected, abs=1e-4)

    def test_only_ml_score_contributes(self):
        result = calculate_confidence(
            event_count=0,
            ml_scores=[100.0],     # ml_avg_score = 1.0
            unique_ioc_count=0,
            protocols=["TCP"],
        )
        expected = DEFAULT_WEIGHTS["ml_avg"] * 1.0
        assert result.confidence == pytest.approx(expected, abs=1e-4)

    def test_only_multi_proto_contributes(self):
        result = calculate_confidence(
            event_count=0,
            ml_scores=[],
            unique_ioc_count=0,
            protocols=["TCP", "UDP"],  # multi_proto_bonus = 1.0
        )
        expected = DEFAULT_WEIGHTS["multi_proto"] * 1.0
        assert result.confidence == pytest.approx(expected, abs=1e-4)

    def test_weighted_sum_matches_manual_calculation(self):
        """Manually compute expected weighted sum and compare."""
        event_count = 100         # css = 100/200 = 0.5
        ml_scores = [80.0]        # mlas = 80/100 = 0.8
        unique_ioc_count = 5      # iod = 5/100 = 0.05
        protocols = ["TCP", "UDP"]  # mpb = 1.0

        result = calculate_confidence(event_count, ml_scores, unique_ioc_count, protocols)

        expected = (
            DEFAULT_WEIGHTS["cluster_size"] * 0.5
            + DEFAULT_WEIGHTS["ml_avg"]      * 0.8
            + DEFAULT_WEIGHTS["ioc_density"] * 0.05
            + DEFAULT_WEIGHTS["multi_proto"] * 1.0
        )
        assert result.confidence == pytest.approx(expected, abs=1e-4)

    def test_component_fields_populated(self):
        result = calculate_confidence(100, [60.0], 10, ["TCP"])
        assert isinstance(result.cluster_size_score, float)
        assert isinstance(result.ml_avg_score, float)
        assert isinstance(result.ioc_density, float)
        assert isinstance(result.multi_proto_bonus, float)

    def test_breakdown_dict_contains_all_keys(self):
        result = calculate_confidence(100, [60.0], 10, ["TCP"])
        bd = result.breakdown
        assert "confidence" in bd
        assert "severity" in bd
        assert "components" in bd
        assert "weights" in bd
        assert "inputs" in bd

    def test_breakdown_components_match_result_fields(self):
        result = calculate_confidence(100, [60.0], 10, ["TCP"])
        comps = result.breakdown["components"]
        assert comps["cluster_size_score"] == result.cluster_size_score
        assert comps["ml_avg_score"]       == result.ml_avg_score
        assert comps["ioc_density"]        == result.ioc_density
        assert comps["multi_proto_bonus"]  == result.multi_proto_bonus

    def test_breakdown_weights_match_defaults(self):
        result = calculate_confidence(100, [60.0], 10, ["TCP"])
        w = result.breakdown["weights"]
        assert w["cluster_size"] == DEFAULT_WEIGHTS["cluster_size"]
        assert w["ml_avg"]       == DEFAULT_WEIGHTS["ml_avg"]
        assert w["ioc_density"]  == DEFAULT_WEIGHTS["ioc_density"]
        assert w["multi_proto"]  == DEFAULT_WEIGHTS["multi_proto"]

    def test_breakdown_inputs_recorded(self):
        result = calculate_confidence(42, [75.0, 80.0], 7, ["TCP", "UDP"])
        inp = result.breakdown["inputs"]
        assert inp["event_count"]      == 42
        assert inp["unique_ioc_count"] == 7
        assert inp["ml_score_count"]   == 2

    def test_confidence_not_nan(self):
        result = calculate_confidence(0, [], 0, [])
        assert not math.isnan(result.confidence)

    def test_confidence_not_inf(self):
        result = calculate_confidence(99999, [100.0] * 100, 99999, ["TCP", "UDP"])
        assert not math.isinf(result.confidence)
        assert result.confidence <= 1.0

    def test_custom_cluster_size_cap(self):
        """With cap=50, 50 events should give cluster_size_score=1.0."""
        result = calculate_confidence(50, [], 0, ["TCP"], cluster_size_cap=50)
        expected = DEFAULT_WEIGHTS["cluster_size"] * 1.0
        assert result.confidence == pytest.approx(expected, abs=1e-4)

    def test_severity_matches_confidence_to_severity(self):
        result = calculate_confidence(120, [70.0], 8, ["TCP"])
        assert result.severity == confidence_to_severity(result.confidence)


# ===========================================================================
# 7. CUSTOM WEIGHTS VALIDATION
# ===========================================================================

class TestCalculateConfidenceWeights:
    """Verify custom weight passing and validation."""

    def test_custom_weights_applied(self):
        # Give all weight to cluster_size: expect confidence = 1.0 * css
        w = {"cluster_size": 1.0, "ml_avg": 0.0, "ioc_density": 0.0, "multi_proto": 0.0}
        result = calculate_confidence(200, [], 0, [], weights=w)
        assert result.confidence == pytest.approx(1.0, abs=1e-4)

    def test_custom_weights_all_to_ml(self):
        w = {"cluster_size": 0.0, "ml_avg": 1.0, "ioc_density": 0.0, "multi_proto": 0.0}
        result = calculate_confidence(0, [100.0], 0, [], weights=w)
        assert result.confidence == pytest.approx(1.0, abs=1e-4)

    def test_weights_not_summing_to_one_raises(self):
        bad_w = {"cluster_size": 0.5, "ml_avg": 0.5, "ioc_density": 0.5, "multi_proto": 0.5}
        with pytest.raises(ValueError, match="sum"):
            calculate_confidence(100, [50.0], 5, ["TCP"], weights=bad_w)

    def test_weights_summing_within_tolerance_ok(self):
        """Weights summing to 1.01 (within ±0.02 tolerance) should not raise."""
        w = {"cluster_size": 0.36, "ml_avg": 0.35, "ioc_density": 0.20, "multi_proto": 0.10}
        result = calculate_confidence(100, [50.0], 5, ["TCP"], weights=w)
        assert 0.0 <= result.confidence <= 1.0

    def test_partial_weight_override(self):
        """Providing only some weight keys merges with defaults."""
        # Only override cluster_size; others stay at defaults
        w = {"cluster_size": 0.25, "ml_avg": 0.45, "ioc_density": 0.20, "multi_proto": 0.10}
        result = calculate_confidence(100, [50.0], 5, ["TCP"], weights=w)
        assert 0.0 <= result.confidence <= 1.0

    def test_weights_stored_in_breakdown(self):
        w = {"cluster_size": 0.25, "ml_avg": 0.45, "ioc_density": 0.20, "multi_proto": 0.10}
        result = calculate_confidence(100, [50.0], 5, ["TCP"], weights=w)
        assert result.breakdown["weights"]["cluster_size"] == 0.25
        assert result.breakdown["weights"]["ml_avg"] == 0.45


# ===========================================================================
# 8. CONFIDENCE RESULT NAMED TUPLE
# ===========================================================================

class TestConfidenceResultNamedTuple:
    """Verify ConfidenceResult fields, types, and immutability."""

    @pytest.fixture
    def result(self):
        return calculate_confidence(100, [70.0], 5, ["TCP", "UDP"])

    def test_has_confidence_field(self, result):
        assert hasattr(result, "confidence")

    def test_has_severity_field(self, result):
        assert hasattr(result, "severity")

    def test_has_cluster_size_score_field(self, result):
        assert hasattr(result, "cluster_size_score")

    def test_has_ml_avg_score_field(self, result):
        assert hasattr(result, "ml_avg_score")

    def test_has_ioc_density_field(self, result):
        assert hasattr(result, "ioc_density")

    def test_has_multi_proto_bonus_field(self, result):
        assert hasattr(result, "multi_proto_bonus")

    def test_has_breakdown_field(self, result):
        assert hasattr(result, "breakdown")

    def test_confidence_is_float(self, result):
        assert isinstance(result.confidence, float)

    def test_severity_is_str(self, result):
        assert isinstance(result.severity, str)

    def test_breakdown_is_dict(self, result):
        assert isinstance(result.breakdown, dict)

    def test_is_namedtuple(self, result):
        assert isinstance(result, tuple)

    def test_immutable(self, result):
        with pytest.raises((AttributeError, TypeError)):
            result.confidence = 0.99  # type: ignore


# ===========================================================================
# 9. SEVERITY THRESHOLD EDGE CASES
# ===========================================================================

class TestSeverityThresholdEdgeCases:
    """Pinpoint boundary values for each tier transition."""

    @pytest.mark.parametrize("confidence,expected_severity", [
        (0.0,   "LOW"),
        (0.001, "LOW"),
        (0.399, "LOW"),
        (0.400, "MEDIUM"),
        (0.401, "MEDIUM"),
        (0.599, "MEDIUM"),
        (0.600, "HIGH"),
        (0.601, "HIGH"),
        (0.799, "HIGH"),
        (0.800, "CRITICAL"),
        (0.801, "CRITICAL"),
        (1.000, "CRITICAL"),
    ])
    def test_boundary(self, confidence, expected_severity):
        assert confidence_to_severity(confidence) == expected_severity

    def test_exactly_0_0_is_low(self):
        assert confidence_to_severity(0.0) == "LOW"

    def test_exactly_0_4_is_medium(self):
        assert confidence_to_severity(0.4) == "MEDIUM"

    def test_exactly_0_6_is_high(self):
        assert confidence_to_severity(0.6) == "HIGH"

    def test_exactly_0_8_is_critical(self):
        assert confidence_to_severity(0.8) == "CRITICAL"


# ===========================================================================
# 10. SCENARIO-BASED SCORING
# ===========================================================================

class TestScenarioBasedScoring:
    """End-to-end scenarios matching realistic campaign cluster profiles."""

    def test_massive_ssh_brute_force(self):
        """Large-scale coordinated SSH attack — expect HIGH or CRITICAL.

        With a single TCP protocol (no multi-proto bonus), the formula gives:
          css=1.0 × 0.35 + mlas≈0.91 × 0.35 + iod≈0.071 × 0.20 + mpb=0.0 × 0.10
          ≈ 0.350 + 0.319 + 0.014 = 0.683  → HIGH
        """
        result = calculate_confidence(
            event_count=350,           # very large cluster → capped at 1.0
            ml_scores=[92.0, 88.0, 95.0, 91.0, 89.0],
            unique_ioc_count=25,
            protocols=["TCP"],
        )
        assert result.severity in ("HIGH", "CRITICAL")
        assert result.confidence >= 0.60

    def test_low_confidence_stray_packets(self):
        """Single stray port scan event — expect LOW."""
        result = calculate_confidence(
            event_count=1,
            ml_scores=[15.0],
            unique_ioc_count=1,
            protocols=["TCP"],
        )
        assert result.severity == "LOW"
        assert result.confidence < 0.40

    def test_medium_multi_vector_campaign(self):
        """Moderate IOC count + multi-protocol — expect at least MEDIUM."""
        result = calculate_confidence(
            event_count=30,
            ml_scores=[55.0, 60.0],
            unique_ioc_count=8,
            protocols=["TCP", "UDP"],
        )
        assert result.severity in ("MEDIUM", "HIGH")

    def test_high_confidence_distributed_attack(self):
        """Distributed attack from multiple IPs across multiple protocols."""
        result = calculate_confidence(
            event_count=180,
            ml_scores=[75.0, 80.0, 85.0],
            unique_ioc_count=15,
            protocols=["TCP", "UDP", "ICMP"],
        )
        assert result.confidence >= 0.60
        assert result.severity in ("HIGH", "CRITICAL")

    def test_pure_ml_high_score_minimal_cluster(self):
        """High ML score but tiny cluster → confidence moderate, not critical."""
        result = calculate_confidence(
            event_count=5,
            ml_scores=[99.0],
            unique_ioc_count=1,
            protocols=["TCP"],
        )
        # ml_avg_score = 0.99 contributes 0.35*0.99 ≈ 0.347
        # cluster_size = 5/200 = 0.025 → 0.35*0.025 ≈ 0.009
        # total < 0.6 → should not be CRITICAL
        assert result.severity in ("LOW", "MEDIUM", "HIGH")
        assert result.confidence < 0.80

    def test_exfiltration_campaign_multi_proto(self):
        """Data exfiltration spanning TCP+UDP with high ML scores."""
        result = calculate_confidence(
            event_count=120,
            ml_scores=[85.0, 90.0, 82.0, 88.0],
            unique_ioc_count=12,
            protocols=["TCP", "UDP"],
        )
        assert result.severity in ("HIGH", "CRITICAL")
        assert result.multi_proto_bonus == 1.0

    def test_confidence_increases_with_more_events(self):
        """Confidence should be higher with more events (all else equal)."""
        low  = calculate_confidence(10,  [50.0], 5, ["TCP"])
        high = calculate_confidence(200, [50.0], 5, ["TCP"])
        assert high.confidence > low.confidence

    def test_confidence_increases_with_higher_ml_scores(self):
        """Confidence should be higher with higher ML scores."""
        low  = calculate_confidence(100, [20.0], 5, ["TCP"])
        high = calculate_confidence(100, [90.0], 5, ["TCP"])
        assert high.confidence > low.confidence

    def test_multi_proto_raises_confidence(self):
        """Multi-protocol flag must raise confidence vs. single-protocol."""
        single = calculate_confidence(100, [70.0], 10, ["TCP"])
        multi  = calculate_confidence(100, [70.0], 10, ["TCP", "UDP"])
        assert multi.confidence > single.confidence

    def test_more_iocs_raises_confidence(self):
        """Higher IOC count (relative to events) must increase confidence."""
        low  = calculate_confidence(100, [70.0], 1,  ["TCP"])
        high = calculate_confidence(100, [70.0], 50, ["TCP"])
        assert high.confidence > low.confidence

    def test_smtp_phishing_campaign(self):
        """SMTP phishing: moderate event count, high ML, multi-protocol."""
        result = calculate_confidence(
            event_count=80,
            ml_scores=[78.0, 82.0],
            unique_ioc_count=6,
            protocols=["TCP", "UDP"],
        )
        assert 0.0 < result.confidence <= 1.0
        assert result.severity in ("MEDIUM", "HIGH", "CRITICAL")

    def test_ftp_credential_stuffing(self):
        result = calculate_confidence(
            event_count=45,
            ml_scores=[65.0, 70.0, 68.0],
            unique_ioc_count=3,
            protocols=["TCP"],
        )
        assert 0.0 < result.confidence <= 1.0

    def test_result_is_reproducible(self):
        """Same inputs always produce the same result."""
        r1 = calculate_confidence(100, [70.0, 80.0], 5, ["TCP", "UDP"])
        r2 = calculate_confidence(100, [70.0, 80.0], 5, ["TCP", "UDP"])
        assert r1.confidence == r2.confidence
        assert r1.severity   == r2.severity
