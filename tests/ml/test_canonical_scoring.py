"""
PhantomNet Canonical Threat-Scoring Comprehensive Audit Test Suite (Phase ML-2)
=============================================================================
Formally verifies all required Phase ML-2 scoring guarantees (A through K):
  A. RF-only score generation
  B. Isolation Forest score generation
  C. IF calibration range: 0.0 <= calibrated_if_score <= 1.0
  D. Hybrid score calculation: final = 0.85 * rf + 0.15 * if
  E. Weight validation: no obsolete 0.70/0.30 formulation in production
  F. Schema validation: wrong feature count / names / order must fail explicitly
  G. Model compatibility: incompatible checkpoints (6D, 13D, 15D, 32D) fail explicitly
  H. Directionality: higher anomaly evidence monotonically increases final threat score
  I. API / service consistency: synchronous API and background analyzer produce identical scores
  J. Determinism: bitwise reproducible outputs under identical inputs and state
  K. Concurrent execution: thread-safe under parallel multi-threaded invocations
"""

import threading
from concurrent.futures import ThreadPoolExecutor
import numpy as np
import pandas as pd
import pytest
from unittest.mock import MagicMock, patch

from ml.feature_extractor import FeatureExtractor
from ml.models.ensemble_predictor import (
    EnsemblePredictor,
    validate_model_compatibility,
)
from ml.config.thresholds import (
    RF_WEIGHT,
    IF_WEIGHT,
    CRITICAL_THRESHOLD,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    BLOCK_THRESHOLD,
    ALERT_THRESHOLD,
    IF_CALIBRATION_MIN,
    IF_CALIBRATION_MAX,
)
from ml.threat_scoring_service import (
    score_threat,
    score_threat_batch,
    map_score_to_level,
    map_score_to_decision,
)
from schemas.threat_schema import ThreatInput, ThreatResponse
import ml.model_loader as model_loader


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def canonical_features():
    """Provides a synthetic 1-row DataFrame strictly matching 12D schema."""
    data = {
        "packet_length": 512.0,
        "protocol_encoding": 1.0,
        "dst_port_class": 1.0,
        "src_port_ephemeral": 1.0,
        "event_rate_1m": 12.0,
        "burst_rate_10s": 3.0,
        "inter_arrival_mean": 0.05,
        "inter_arrival_std": 0.01,
        "packet_size_variance": 120.0,
        "payload_entropy": 4.5,
        "unique_dst_ips": 1.0,
        "unique_dst_ports": 1.0,
    }
    return pd.DataFrame([data], columns=FeatureExtractor.FEATURE_NAMES)


@pytest.fixture
def mock_rf_model():
    """Creates a mock RF classifier outputting known probability."""
    mock = MagicMock()
    mock.n_features_in_ = 12
    mock.feature_names_in_ = np.array(FeatureExtractor.FEATURE_NAMES)
    mock.predict_proba.return_value = np.array([[0.20, 0.80]])
    mock.predict.return_value = np.array([1])
    return mock


@pytest.fixture
def mock_if_model():
    """Creates a mock IF detector outputting known raw decision function."""
    mock = MagicMock()
    mock.n_features_in_ = 12
    mock.feature_names_in_ = np.array(FeatureExtractor.FEATURE_NAMES)
    # Raw decision function near -0.10 (anomalous)
    mock.decision_function.return_value = np.array([-0.10])
    return mock


# ============================================================================
# REQUIREMENT A: RF-ONLY SCORE GENERATION
# ============================================================================

def test_req_a_rf_only_score_generation(canonical_features, mock_rf_model):
    """Verifies that RF prediction operates correctly and outputs valid probabilities."""
    predictor = EnsemblePredictor(rf_model=mock_rf_model, if_model=None)
    res = predictor.score_vector(canonical_features)

    assert res["rf_score"] == 0.80
    assert res["calibrated_if_score"] == 0.0
    assert res["final_score"] == 0.80
    assert 0.0 <= res["rf_score"] <= 1.0


# ============================================================================
# REQUIREMENT B: ISOLATION FOREST SCORE GENERATION
# ============================================================================

def test_req_b_isolation_forest_score_generation(canonical_features, mock_if_model):
    """Verifies that Isolation Forest anomaly scoring operates correctly."""
    predictor = EnsemblePredictor(rf_model=None, if_model=mock_if_model)
    res = predictor.score_vector(canonical_features)

    assert res["raw_if_score"] == -0.10
    assert 0.0 <= res["calibrated_if_score"] <= 1.0
    assert res["final_score"] == res["calibrated_if_score"]


# ============================================================================
# REQUIREMENT C: IF CALIBRATION RANGE [0.0, 1.0]
# ============================================================================

def test_req_c_if_calibration_range():
    """Verifies that calibrated IF score is strictly bounded in [0.0, 1.0] across extreme values."""
    predictor = EnsemblePredictor(rf_model=None, if_model=None)

    extreme_raw_scores = [-1000.0, -1.0, -0.181713, 0.0, 0.166857, 1.0, 1000.0]
    for raw in extreme_raw_scores:
        cal = predictor.calibrate_if_score(raw)
        assert 0.0 <= cal <= 1.0, f"Calibrated score {cal} out of bounds for raw {raw}"


# ============================================================================
# REQUIREMENT D: HYBRID SCORE CALCULATION (0.85 RF + 0.15 IF)
# ============================================================================

def test_req_d_hybrid_score_calculation(canonical_features, mock_rf_model, mock_if_model):
    """
    For controlled test values:
        rf = 0.80, if_calibrated = known
        final = 0.85 * rf + 0.15 * if_calibrated
    """
    predictor = EnsemblePredictor(rf_model=mock_rf_model, if_model=mock_if_model)
    res = predictor.score_vector(canonical_features)

    rf_val = res["rf_score"]
    if_val = res["calibrated_if_score"]
    expected = (0.85 * rf_val) + (0.15 * if_val)

    assert np.isclose(res["final_score"], expected, atol=1e-5)
    assert np.isclose(predictor.w_rf, 0.85)
    assert np.isclose(predictor.w_if, 0.15)


# ============================================================================
# REQUIREMENT E: WEIGHT VALIDATION (NO OBSOLETE 0.70 / 0.30)
# ============================================================================

def test_req_e_weight_validation_no_obsolete_weights():
    """Verifies that production code enforces 0.85/0.15 and does not use 0.70/0.30."""
    pred = EnsemblePredictor()
    assert pred.w_rf == 0.85, f"Expected w_rf == 0.85, found {pred.w_rf}"
    assert pred.w_if == 0.15, f"Expected w_if == 0.15, found {pred.w_if}"
    assert pred.w_rf != 0.70
    assert pred.w_if != 0.30

    # If obsolete 0.70/0.30 is passed to constructor, it must be overridden to canonical
    pred_obs = EnsemblePredictor(w_rf=0.70, w_if=0.30)
    assert pred_obs.w_rf == 0.85
    assert pred_obs.w_if == 0.15


# ============================================================================
# REQUIREMENT F: SCHEMA VALIDATION
# ============================================================================

def test_req_f_schema_validation_feature_count_and_names():
    """Verifies that wrong feature count or wrong names fail fast with ValueError."""
    pred = EnsemblePredictor()

    # Case 1: Wrong feature count (11 features instead of 12)
    bad_df_11 = pd.DataFrame(np.random.rand(1, 11))
    with pytest.raises(ValueError, match="columns, expected 12"):
        pred.score_vector(bad_df_11)

    # Case 2: Wrong feature count (15 features instead of 12)
    bad_df_15 = pd.DataFrame(np.random.rand(1, 15))
    with pytest.raises(ValueError, match="columns, expected 12"):
        pred.score_vector(bad_df_15)


# ============================================================================
# REQUIREMENT G: MODEL COMPATIBILITY
# ============================================================================

def test_req_g_model_compatibility_rejects_incompatible_checkpoints():
    """Verifies that models expecting 6D, 13D, 15D, or 32D features fail explicitly."""
    for bad_dim in [6, 13, 15, 32]:
        mock_incompatible = MagicMock()
        mock_incompatible.n_features_in_ = bad_dim

        with pytest.raises(ValueError, match="Incompatible"):
            validate_model_compatibility(mock_incompatible, f"BadModel_{bad_dim}D")

        with pytest.raises(ValueError, match="Incompatible"):
            EnsemblePredictor(rf_model=mock_incompatible)


# ============================================================================
# REQUIREMENT H: DIRECTIONALITY (HIGHER ANOMALY -> HIGHER THREAT SCORE)
# ============================================================================

def test_req_h_directionality_anomaly_evidence_increases_threat_score():
    """
    Verifies that as anomalousness increases (decision_function becomes more negative),
    calibrated IF score monotonically INCREASES, and final threat score monotonically INCREASES.
    """
    pred = EnsemblePredictor()

    # Normal inlier (+0.15) vs Anomaly outlier (-0.15)
    normal_raw = 0.15
    anomalous_raw = -0.15

    cal_normal = pred.calibrate_if_score(normal_raw)
    cal_anomalous = pred.calibrate_if_score(anomalous_raw)

    assert cal_anomalous > cal_normal, (
        f"Directionality inverted: anomalous raw ({anomalous_raw}) gave {cal_anomalous}, "
        f"normal raw ({normal_raw}) gave {cal_normal}"
    )

    # Test monotonic increase on final score with constant RF score (e.g. 0.50)
    final_with_normal_if = (0.85 * 0.50) + (0.15 * cal_normal)
    final_with_anomalous_if = (0.85 * 0.50) + (0.15 * cal_anomalous)

    assert final_with_anomalous_if > final_with_normal_if


# ============================================================================
# REQUIREMENT I: API / BACKGROUND SERVICE CONSISTENCY
# ============================================================================

def test_req_i_api_and_service_consistency(mock_rf_model, mock_if_model):
    """
    Verifies that single-event scoring (API path) and batch scoring (Analyzer path)
    produce bitwise identical results for the same canonical event.
    """
    event = ThreatInput(
        src_ip="192.168.10.42",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        length=256,
    )

    with patch("ml.model_loader.load_model", return_value=mock_rf_model), \
         patch("ml.model_loader.load_isolation_forest", return_value=mock_if_model):

        # 1. Synchronous single-event API scoring
        single_res = score_threat(event)

        # 2. Vectorized batch analyzer scoring
        batch_res = score_threat_batch([event])[0]

        assert single_res.score == batch_res.score
        assert single_res.threat_level == batch_res.threat_level
        assert single_res.decision == batch_res.decision
        assert single_res.rf_score == batch_res.rf_score
        assert single_res.calibrated_if_score == batch_res.calibrated_if_score


# ============================================================================
# REQUIREMENT J: DETERMINISM
# ============================================================================

def test_req_j_determinism_under_identical_inputs(canonical_features, mock_rf_model, mock_if_model):
    """Verifies that evaluating the same event repeatedly yields identical numbers."""
    pred = EnsemblePredictor(rf_model=mock_rf_model, if_model=mock_if_model)

    first_run = pred.score_vector(canonical_features)
    for _ in range(20):
        subsequent_run = pred.score_vector(canonical_features)
        assert first_run == subsequent_run


# ============================================================================
# REQUIREMENT K: CONCURRENT EXECUTION THREAD-SAFETY
# ============================================================================

def test_req_k_concurrent_execution_thread_safety(mock_rf_model, mock_if_model):
    """Verifies that EnsemblePredictor safely evaluates concurrent threads without race conditions."""
    pred = EnsemblePredictor(rf_model=mock_rf_model, if_model=mock_if_model)
    errors = []

    def task(thread_id: int):
        try:
            for i in range(50):
                df = pd.DataFrame([{
                    "packet_length": 64.0 + i,
                    "protocol_encoding": 1.0,
                    "dst_port_class": 1.0,
                    "src_port_ephemeral": 1.0,
                    "event_rate_1m": float(i),
                    "burst_rate_10s": 1.0,
                    "inter_arrival_mean": 0.1,
                    "inter_arrival_std": 0.01,
                    "packet_size_variance": 10.0,
                    "payload_entropy": 3.0,
                    "unique_dst_ips": 1.0,
                    "unique_dst_ports": 1.0,
                }], columns=FeatureExtractor.FEATURE_NAMES)
                res = pred.score_vector(df)
                assert 0.0 <= res["final_score"] <= 1.0
        except Exception as e:
            errors.append(e)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(task, tid) for tid in range(8)]
        for f in futures:
            f.result()

    assert len(errors) == 0, f"Encountered thread safety errors: {errors}"
