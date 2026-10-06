"""
tests/noc/test_threat_score_boundaries.py
-----------------------------------------
Validates canonical threat score boundaries across NOC backend services.
Canonical Thresholds:
  CRITICAL : >= 0.80
  HIGH     : >= 0.60
  MEDIUM   : >= 0.40
  LOW      : <  0.40

Boundary Values Tested:
  0.00, 0.39, 0.40, 0.59, 0.60, 0.79, 0.80, 1.00
"""
import pytest
from api.attack_attribution import _normalize_score, _sophistication
from api.predictive import _classify_risk


def test_normalize_score_boundaries():
    """Verify normalization preserves canonical 0.0 - 1.0 range and rescales 0-100 inputs."""
    assert _normalize_score(0.0) == 0.0
    assert _normalize_score(0.39) == 0.39
    assert _normalize_score(0.40) == 0.40
    assert _normalize_score(0.59) == 0.59
    assert _normalize_score(0.60) == 0.60
    assert _normalize_score(0.79) == 0.79
    assert _normalize_score(0.80) == 0.80
    assert _normalize_score(1.00) == 1.00

    # Rescaling legacy 0-100 scores
    assert _normalize_score(80.0) == 0.80
    assert _normalize_score(60.0) == 0.60
    assert _normalize_score(40.0) == 0.40
    assert _normalize_score(100.0) == 1.00

    # None and negative handling
    assert _normalize_score(None) == 0.0
    assert _normalize_score(-5.0) == 0.0


def test_attribution_sophistication_boundaries():
    """Verify sophistication tiers map accurately to canonical boundaries."""
    # Low: < 0.40
    assert _sophistication(0.00, 1)["level"].startswith("Low Threat")
    assert _sophistication(0.39, 5)["level"].startswith("Low Threat")

    # Medium: >= 0.40 and < 0.60
    assert _sophistication(0.40, 1)["level"].startswith("Medium Threat")
    assert _sophistication(0.59, 5)["level"].startswith("Medium Threat")

    # High: >= 0.60 and < 0.80
    assert _sophistication(0.60, 1)["level"].startswith("High Threat")
    assert _sophistication(0.79, 5)["level"].startswith("High Threat")

    # Critical: >= 0.80 (with persistence tier)
    assert _sophistication(0.80, 10)["level"].startswith("Critical Threat")
    assert _sophistication(1.00, 15)["level"].startswith("Critical Threat")


def test_predictive_risk_classification_boundaries():
    """Verify predictive risk classification matches canonical thresholds (80, 60, 40)."""
    assert _classify_risk(0.0) == "LOW"
    assert _classify_risk(39.0) == "LOW"
    assert _classify_risk(39.9) == "LOW"

    assert _classify_risk(40.0) == "MEDIUM"
    assert _classify_risk(59.0) == "MEDIUM"
    assert _classify_risk(59.9) == "MEDIUM"

    assert _classify_risk(60.0) == "HIGH"
    assert _classify_risk(79.0) == "HIGH"
    assert _classify_risk(79.9) == "HIGH"

    assert _classify_risk(80.0) == "CRITICAL"
    assert _classify_risk(100.0) == "CRITICAL"
