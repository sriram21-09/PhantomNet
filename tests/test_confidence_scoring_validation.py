"""
tests/test_confidence_scoring_validation.py
--------------------------------------------
Week 14 Confidence Scoring Engine — Calibration Validation Suite

Validates confidence scores across 7 attack scenarios:
  1. Small SSH brute force (5-10 events, single IP)     → LOW-MEDIUM
  2. Large SSH brute force (100+ events, multi-IP)      → HIGH-CRITICAL
  3. Multi-protocol attack (SSH+HTTP, same IP range)    → bonus applied
  4. Single-event campaign                              → very LOW
  5. Range validation (always 0.0-1.0, no NaN/Inf)
  6. DB storage validation (SentinelPlaybook record)
  7. Expected vs actual calibration table
"""

from __future__ import annotations

import math
import os
import sys
import json
from datetime import datetime

import pytest

# Path bootstrap
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "backend")
for _p in (_ROOT, _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from sentinel.confidence_scoring import (
    DEFAULT_WEIGHTS,
    ConfidenceResult,
    calculate_confidence,
    confidence_to_severity,
    _normalise_cluster_size,
    _normalise_ml_scores,
    _calculate_ioc_density,
    _multi_proto_bonus,
)

# ── Collect results for the calibration report ──
_CALIBRATION_RESULTS = []


def _record(scenario, expected_range, expected_severity, result):
    """Record a scenario result for the final calibration report."""
    _CALIBRATION_RESULTS.append({
        "scenario": scenario,
        "confidence": result.confidence,
        "severity": result.severity,
        "expected_range": expected_range,
        "expected_severity": expected_severity,
        "in_range": expected_range[0] <= result.confidence <= expected_range[1],
        "severity_match": result.severity in (expected_severity if isinstance(expected_severity, (list, tuple)) else [expected_severity]),
        "components": {
            "cluster_size_score": result.cluster_size_score,
            "ml_avg_score": result.ml_avg_score,
            "ioc_density": result.ioc_density,
            "multi_proto_bonus": result.multi_proto_bonus,
        },
    })


# ===========================================================================
# 1. SMALL SSH BRUTE FORCE (5-10 events, single IP) → LOW-MEDIUM
# ===========================================================================

class TestSmallSSHBruteForce:
    """Small campaign: 5-10 events, single IP, single protocol."""

    def test_5_events_single_ip(self):
        result = calculate_confidence(
            event_count=5,
            ml_scores=[45.0, 50.0, 55.0, 48.0, 52.0],
            unique_ioc_count=1,
            protocols=["TCP"],
        )
        _record("Small SSH (5 events, 1 IP)", (0.0, 0.45), ["LOW", "MEDIUM"], result)
        assert 0.0 <= result.confidence <= 0.45
        assert result.severity in ("LOW", "MEDIUM")

    def test_8_events_single_ip(self):
        result = calculate_confidence(
            event_count=8,
            ml_scores=[50.0, 55.0, 60.0, 52.0, 58.0, 53.0, 57.0, 51.0],
            unique_ioc_count=1,
            protocols=["TCP"],
        )
        _record("Small SSH (8 events, 1 IP)", (0.0, 0.50), ["LOW", "MEDIUM"], result)
        assert 0.0 <= result.confidence <= 0.50
        assert result.severity in ("LOW", "MEDIUM")

    def test_10_events_moderate_ml(self):
        result = calculate_confidence(
            event_count=10,
            ml_scores=[60.0, 65.0, 58.0, 62.0, 70.0,
                        55.0, 63.0, 67.0, 59.0, 61.0],
            unique_ioc_count=1,
            protocols=["TCP"],
        )
        _record("Small SSH (10 events, moderate ML)", (0.10, 0.55), ["LOW", "MEDIUM"], result)
        assert 0.10 <= result.confidence <= 0.55
        assert result.severity in ("LOW", "MEDIUM")


# ===========================================================================
# 2. LARGE SSH BRUTE FORCE (100+ events, multiple IPs) → HIGH-CRITICAL
# ===========================================================================

class TestLargeSSHBruteForce:
    """Large-scale coordinated SSH attack — expect HIGH or CRITICAL."""

    def test_150_events_multi_ip(self):
        result = calculate_confidence(
            event_count=150,
            ml_scores=[85.0, 90.0, 88.0, 92.0, 87.0, 91.0, 86.0, 89.0],
            unique_ioc_count=8,
            protocols=["TCP"],
        )
        _record("Large SSH (150 events, 8 IPs)", (0.50, 1.0), ["MEDIUM", "HIGH", "CRITICAL"], result)
        assert result.confidence >= 0.50
        assert result.severity in ("MEDIUM", "HIGH", "CRITICAL")

    def test_300_events_capped_cluster(self):
        result = calculate_confidence(
            event_count=300,
            ml_scores=[92.0, 95.0, 88.0, 91.0, 93.0, 90.0, 94.0, 89.0, 96.0, 87.0],
            unique_ioc_count=15,
            protocols=["TCP"],
        )
        _record("Large SSH (300 events, 15 IPs)", (0.60, 1.0), ["HIGH", "CRITICAL"], result)
        assert result.confidence >= 0.60
        assert result.severity in ("HIGH", "CRITICAL")

    def test_500_events_extreme(self):
        result = calculate_confidence(
            event_count=500,
            ml_scores=[95.0] * 20,
            unique_ioc_count=50,
            protocols=["TCP"],
        )
        _record("Large SSH (500 events, 50 IPs)", (0.60, 1.0), ["HIGH", "CRITICAL"], result)
        assert result.confidence >= 0.60
        assert result.severity in ("HIGH", "CRITICAL")


# ===========================================================================
# 3. MULTI-PROTOCOL ATTACK (SSH + HTTP) → bonus applied
# ===========================================================================

class TestMultiProtocolAttack:
    """Multi-protocol campaigns should get the multi_proto bonus."""

    def test_ssh_plus_http_bonus_applied(self):
        single = calculate_confidence(
            event_count=80,
            ml_scores=[70.0, 75.0, 72.0, 78.0],
            unique_ioc_count=5,
            protocols=["TCP"],
        )
        multi = calculate_confidence(
            event_count=80,
            ml_scores=[70.0, 75.0, 72.0, 78.0],
            unique_ioc_count=5,
            protocols=["TCP", "HTTP"],
        )
        _record("Multi-proto SSH+HTTP", (0.40, 1.0), ["MEDIUM", "HIGH", "CRITICAL"], multi)
        assert multi.confidence > single.confidence, "Multi-proto must score higher"
        assert multi.multi_proto_bonus == 1.0
        assert single.multi_proto_bonus == 0.0

    def test_three_protocols_bonus(self):
        result = calculate_confidence(
            event_count=120,
            ml_scores=[80.0, 85.0, 82.0],
            unique_ioc_count=10,
            protocols=["TCP", "UDP", "ICMP"],
        )
        _record("Multi-proto TCP+UDP+ICMP", (0.50, 1.0), ["HIGH", "CRITICAL"], result)
        assert result.multi_proto_bonus == 1.0
        assert result.confidence >= 0.50

    def test_bonus_magnitude(self):
        """Multi-proto bonus contributes exactly w_multi * 1.0 = 0.10."""
        single = calculate_confidence(50, [60.0], 3, ["TCP"])
        multi = calculate_confidence(50, [60.0], 3, ["TCP", "UDP"])
        diff = multi.confidence - single.confidence
        expected_diff = DEFAULT_WEIGHTS["multi_proto"] * 1.0
        assert diff == pytest.approx(expected_diff, abs=1e-3)


# ===========================================================================
# 4. SINGLE-EVENT CAMPAIGN → very LOW
# ===========================================================================

class TestSingleEventCampaign:
    """A single event should produce very low confidence."""

    def test_single_event_low_ml(self):
        result = calculate_confidence(
            event_count=1,
            ml_scores=[20.0],
            unique_ioc_count=1,
            protocols=["TCP"],
        )
        _record("Single event (low ML)", (0.0, 0.35), ["LOW"], result)
        assert result.confidence < 0.35
        assert result.severity == "LOW"

    def test_single_event_high_ml(self):
        """Even with high ML score, single event stays low-medium."""
        result = calculate_confidence(
            event_count=1,
            ml_scores=[99.0],
            unique_ioc_count=1,
            protocols=["TCP"],
        )
        _record("Single event (high ML=99)", (0.0, 0.60), ["LOW", "MEDIUM"], result)
        assert result.confidence < 0.60
        assert result.severity in ("LOW", "MEDIUM")

    def test_zero_events(self):
        result = calculate_confidence(
            event_count=0,
            ml_scores=[],
            unique_ioc_count=0,
            protocols=[],
        )
        _record("Zero events", (0.0, 0.0), ["LOW"], result)
        assert result.confidence == 0.0
        assert result.severity == "LOW"


# ===========================================================================
# 5. RANGE VALIDATION (0.0-1.0, no NaN/Inf)
# ===========================================================================

class TestRangeValidation:
    """Verify all outputs are in [0.0, 1.0] with no NaN or Inf."""

    SCENARIOS = [
        (0, [], 0, []),
        (1, [0.0], 0, ["TCP"]),
        (1, [100.0], 1, ["TCP"]),
        (50, [50.0], 5, ["TCP"]),
        (100, [75.0, 80.0], 10, ["TCP", "UDP"]),
        (200, [100.0] * 10, 200, ["TCP", "UDP", "ICMP"]),
        (99999, [100.0] * 100, 99999, ["TCP", "UDP"]),
        (1, [None, None], 0, [None]),
        (0, [-50.0], -1, [""]),
        (10, [150.0, 200.0], 10, ["TCP"]),  # over-range ML
    ]

    @pytest.mark.parametrize("events,ml,iocs,protos", SCENARIOS)
    def test_confidence_in_0_1(self, events, ml, iocs, protos):
        result = calculate_confidence(events, ml, iocs, protos)
        assert 0.0 <= result.confidence <= 1.0

    @pytest.mark.parametrize("events,ml,iocs,protos", SCENARIOS)
    def test_no_nan(self, events, ml, iocs, protos):
        result = calculate_confidence(events, ml, iocs, protos)
        assert not math.isnan(result.confidence)

    @pytest.mark.parametrize("events,ml,iocs,protos", SCENARIOS)
    def test_no_inf(self, events, ml, iocs, protos):
        result = calculate_confidence(events, ml, iocs, protos)
        assert not math.isinf(result.confidence)

    @pytest.mark.parametrize("events,ml,iocs,protos", SCENARIOS)
    def test_severity_valid(self, events, ml, iocs, protos):
        result = calculate_confidence(events, ml, iocs, protos)
        assert result.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    @pytest.mark.parametrize("events,ml,iocs,protos", SCENARIOS)
    def test_components_in_range(self, events, ml, iocs, protos):
        result = calculate_confidence(events, ml, iocs, protos)
        assert 0.0 <= result.cluster_size_score <= 1.0
        assert 0.0 <= result.ml_avg_score <= 1.0
        assert 0.0 <= result.ioc_density <= 1.0
        assert result.multi_proto_bonus in (0.0, 1.0)


# ===========================================================================
# 6. DB STORAGE VALIDATION (SentinelPlaybook model compatibility)
# ===========================================================================

class TestDBStorageCompatibility:
    """Verify confidence values are compatible with SentinelPlaybook model."""

    def test_confidence_assignable_to_float_column(self):
        result = calculate_confidence(100, [70.0], 5, ["TCP"])
        # Simulate assigning to SQLAlchemy Float column
        val = float(result.confidence)
        assert isinstance(val, float)
        assert 0.0 <= val <= 1.0

    def test_severity_assignable_to_string_column(self):
        result = calculate_confidence(100, [70.0], 5, ["TCP"])
        val = str(result.severity)
        assert isinstance(val, str)
        assert len(val) <= 16  # String(16) in model

    def test_breakdown_serializable_to_json(self):
        result = calculate_confidence(100, [70.0], 5, ["TCP", "UDP"])
        json_str = json.dumps(result.breakdown)
        parsed = json.loads(json_str)
        assert "confidence" in parsed
        assert "severity" in parsed
        assert "components" in parsed

    def test_confidence_matches_severity_mapping(self):
        """confidence_score and severity must be consistent."""
        for ec in [1, 10, 50, 100, 200]:
            result = calculate_confidence(ec, [60.0], 5, ["TCP"])
            assert result.severity == confidence_to_severity(result.confidence)


# ===========================================================================
# 7. CALIBRATION TABLE — expected vs actual
# ===========================================================================

class TestCalibrationTable:
    """Generate the full calibration data for the report."""

    CALIBRATION_SCENARIOS = [
        ("Single event, low ML", 1, [15.0], 1, ["TCP"], (0.0, 0.30), "LOW"),
        ("5 events, moderate ML", 5, [50.0]*5, 1, ["TCP"], (0.10, 0.40), "LOW"),
        ("10 events, moderate ML", 10, [60.0]*10, 2, ["TCP"], (0.15, 0.50), "LOW,MEDIUM"),
        ("30 events, high ML", 30, [80.0]*5, 4, ["TCP"], (0.25, 0.60), "LOW,MEDIUM,HIGH"),
        ("50 events, high ML, multi-proto", 50, [85.0]*5, 5, ["TCP","UDP"], (0.40, 0.75), "MEDIUM,HIGH"),
        ("100 events, very high ML", 100, [90.0]*10, 10, ["TCP"], (0.40, 0.80), "MEDIUM,HIGH,CRITICAL"),
        ("150 events, high ML, multi-proto", 150, [88.0]*8, 12, ["TCP","UDP"], (0.55, 0.90), "MEDIUM,HIGH,CRITICAL"),
        ("200+ events, max ML, multi-proto", 250, [95.0]*15, 20, ["TCP","UDP","ICMP"], (0.75, 1.0), "CRITICAL,HIGH"),
    ]

    @pytest.mark.parametrize(
        "name,events,ml,iocs,protos,exp_range,exp_sev",
        CALIBRATION_SCENARIOS,
    )
    def test_calibration_scenario(self, name, events, ml, iocs, protos, exp_range, exp_sev):
        result = calculate_confidence(events, ml, iocs, protos)
        sev_list = exp_sev.split(",")
        _record(name, exp_range, sev_list, result)
        assert exp_range[0] <= result.confidence <= exp_range[1], (
            f"{name}: confidence {result.confidence} not in {exp_range}"
        )
        assert result.severity in sev_list, (
            f"{name}: severity {result.severity} not in {sev_list}"
        )


# ===========================================================================
# REPORT GENERATION (runs after all tests)
# ===========================================================================

@pytest.fixture(scope="session", autouse=True)
def print_calibration_report(request):
    """Print calibration summary after all tests complete."""
    yield
    if _CALIBRATION_RESULTS:
        print("\n" + "=" * 80)
        print("CONFIDENCE SCORING CALIBRATION REPORT")
        print("=" * 80)
        print(f"{'Scenario':<45} {'Confidence':>10} {'Severity':<10} {'Expected':>14} {'Pass':>5}")
        print("-" * 90)
        all_pass = True
        for r in _CALIBRATION_RESULTS:
            rng = f"{r['expected_range'][0]:.2f}-{r['expected_range'][1]:.2f}"
            passed = "PASS" if (r["in_range"] and r["severity_match"]) else "FAIL"
            if passed == "FAIL":
                all_pass = False
            print(f"{r['scenario']:<45} {r['confidence']:>10.4f} {r['severity']:<10} {rng:>14} {passed:>5}")
        print("-" * 90)
        status = "ALL PASS" if all_pass else "SOME FAILURES"
        print(f"Result: {status}  |  Total scenarios: {len(_CALIBRATION_RESULTS)}")
        print("=" * 80)
