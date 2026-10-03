"""
PhantomNet Canonical Threat Scoring & Severity Thresholds Configuration
======================================================================
Defines the authoritative repository-wide constants for:
- Hybrid ensemble weights (Phase ML-2 Canonical Formulation)
- Threat severity classification thresholds
- Automated enforcement decision thresholds
- Isolation Forest anomaly calibration bounds
"""

# Authoritative 12D Feature Contract (Phase ML-3)
try:
    from backend.ml.config.feature_schema import (
        CANONICAL_FEATURE_NAMES,
        CANONICAL_FEATURE_COUNT,
        CANONICAL_TARGET_NAME,
        SCHEMA_VERSION,
        validate_feature_vector,
        validate_feature_dict,
    )
except ImportError:
    from ml.config.feature_schema import (
        CANONICAL_FEATURE_NAMES,
        CANONICAL_FEATURE_COUNT,
        CANONICAL_TARGET_NAME,
        SCHEMA_VERSION,
        validate_feature_vector,
        validate_feature_dict,
    )

# ============================================================================
# 1. CANONICAL ENSEMBLE WEIGHTS (Phase ML-2 Specification)
# ============================================================================
# Verified via grid search on held-out validation data (REMEDIATION_REPORT.md / CLM-08)
RF_WEIGHT: float = 0.85
IF_WEIGHT: float = 0.15

# Obsolete formulation weights (explicitly rejected by Rule 3)
OBSOLETE_RF_WEIGHT: float = 0.70
OBSOLETE_IF_WEIGHT: float = 0.30

# ============================================================================
# 2. SEVERITY CLASSIFICATION THRESHOLDS
# ============================================================================
# Base severity cutoffs:
#   CRITICAL: score >= 0.80
#   HIGH:     0.60 <= score < 0.80
#   MEDIUM:   0.40 <= score < 0.60
#   LOW:      score < 0.40
CRITICAL_THRESHOLD: float = 0.80
HIGH_THRESHOLD: float = 0.60
MEDIUM_THRESHOLD: float = 0.40
LOW_MAX_THRESHOLD: float = 0.40

# ============================================================================
# 3. ENFORCEMENT DECISION THRESHOLDS
# ============================================================================
# Automated response routing:
#   BLOCK: score >= 0.80 (or explicit malicious ground-truth context)
#   ALERT: 0.50 <= score < 0.80
#   ALLOW: score < 0.50
BLOCK_THRESHOLD: float = 0.80
ALERT_THRESHOLD: float = 0.50

# ============================================================================
# 4. ISOLATION FOREST CALIBRATION PARAMETERS
# ============================================================================
# Empirical reference bounds of decision_function(x) on training distribution
# S_IF = 1.0 - (s(x) - IF_CALIBRATION_MIN) / (IF_CALIBRATION_MAX - IF_CALIBRATION_MIN + 1e-9)
# Clamped to [0.0, 1.0].
IF_CALIBRATION_MIN: float = -0.181713
IF_CALIBRATION_MAX: float = 0.166857
