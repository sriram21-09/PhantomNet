"""
PHANTOMNET PHASE ML-3: CANONICAL 12D FEATURE CONTRACT & QUARANTINE TEST SUITE
=============================================================================
Formally verifies:
  A. exact feature count = 12
  B. exact feature names
  C. exact feature ordering
  D. missing feature rejection
  E. extra feature / leakage rejection
  F. non-numeric rejection
  G. non-finite value handling (NaN, Inf, -Inf)
  H. canonical model accepts 12D input
  I. 6D model rejection
  J. 13D model rejection
  K. 15D model rejection
  L. 32D model rejection
  M. no positional truncation (fails on 13D+ inputs)
  N. no silent padding (fails on <12D inputs)
  O. API/service canonical schema consistency
  P. deterministic feature ordering
  Q. model metadata/schema mismatch rejection (e.g. 12D host features)
"""

import os
import sys
import pytest
import numpy as np
import pandas as pd
from typing import Dict, Any

from backend.ml.config.feature_schema import (
    CANONICAL_FEATURE_NAMES,
    CANONICAL_FEATURE_COUNT,
    CANONICAL_TARGET_NAME,
    SCHEMA_VERSION,
    PROHIBITED_LEAKAGE_COLUMNS,
    KNOWN_INCOMPATIBLE_DIMENSIONS,
    validate_feature_vector,
    validate_feature_dict,
    dict_to_canonical_vector,
)
from backend.ml.feature_extractor import FeatureExtractor
from backend.ml.models.ensemble_predictor import (
    EnsemblePredictor,
    validate_model_compatibility,
)
from backend.ml.model_loader import (
    get_ensemble,
    get_model,
    get_isolation_forest,
    validate_checkpoint_schema,
    inspect_model_checkpoint,
    STATUS_CANONICAL,
    STATUS_QUARANTINED,
)
from backend.ml.threat_scoring_service import score_threat
from backend.schemas.threat_schema import ThreatInput


# ============================================================================
# REQUIREMENT A: EXACT FEATURE COUNT = 12
# ============================================================================

def test_req_a_exact_feature_count():
    assert CANONICAL_FEATURE_COUNT == 12
    assert len(CANONICAL_FEATURE_NAMES) == 12
    assert len(FeatureExtractor.FEATURE_NAMES) == 12
    extractor = FeatureExtractor()
    sample_event = {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": "TCP", "length": 100}
    features = extractor.extract_features(sample_event)
    assert len(features) == 12
    vector = extractor.extract_vector(sample_event)
    assert len(vector) == 12


# ============================================================================
# REQUIREMENT B: EXACT FEATURE NAMES
# ============================================================================

def test_req_b_exact_feature_names():
    expected = {
        "packet_length",
        "protocol_encoding",
        "dst_port_class",
        "src_port_ephemeral",
        "event_rate_1m",
        "burst_rate_10s",
        "inter_arrival_mean",
        "inter_arrival_std",
        "packet_size_variance",
        "payload_entropy",
        "unique_dst_ips",
        "unique_dst_ports",
    }
    assert set(CANONICAL_FEATURE_NAMES) == expected
    assert set(FeatureExtractor.FEATURE_NAMES) == expected


# ============================================================================
# REQUIREMENT C: EXACT FEATURE ORDERING
# ============================================================================

def test_req_c_exact_feature_ordering():
    expected_order = (
        "packet_length",
        "protocol_encoding",
        "dst_port_class",
        "src_port_ephemeral",
        "event_rate_1m",
        "burst_rate_10s",
        "inter_arrival_mean",
        "inter_arrival_std",
        "packet_size_variance",
        "payload_entropy",
        "unique_dst_ips",
        "unique_dst_ports",
    )
    assert CANONICAL_FEATURE_NAMES == expected_order
    assert tuple(FeatureExtractor.FEATURE_NAMES) == expected_order


# ============================================================================
# REQUIREMENT D: MISSING FEATURE REJECTION
# ============================================================================

def test_req_d_missing_feature_rejection():
    # Incomplete dictionary missing unique_dst_ports
    incomplete_dict = {name: 1.0 for name in CANONICAL_FEATURE_NAMES if name != "unique_dst_ports"}
    with pytest.raises(ValueError, match="Missing required canonical features"):
        validate_feature_dict(incomplete_dict, require_all=True)

    # DataFrame missing a column
    df_missing = pd.DataFrame([incomplete_dict])
    with pytest.raises(ValueError, match="Feature schema violation"):
        validate_feature_vector(df_missing)


# ============================================================================
# REQUIREMENT E: EXTRA FEATURE / LEAKAGE REJECTION
# ============================================================================

def test_req_e_extra_feature_leakage_rejection():
    for leakage_col in PROHIBITED_LEAKAGE_COLUMNS:
        bad_dict = {name: 1.0 for name in CANONICAL_FEATURE_NAMES}
        bad_dict[leakage_col] = 1.0
        with pytest.raises(ValueError, match="Target/Label leakage detected"):
            validate_feature_dict(bad_dict)


# ============================================================================
# REQUIREMENT F: NON-NUMERIC REJECTION
# ============================================================================

def test_req_f_non_numeric_rejection():
    bad_dict = {name: 1.0 for name in CANONICAL_FEATURE_NAMES}
    bad_dict["packet_length"] = "not_a_number"
    with pytest.raises(ValueError, match="could not be converted to float"):
        validate_feature_dict(bad_dict)

    bad_vector = [1.0, "text", 2.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
    with pytest.raises(TypeError, match="Non-numeric values in feature vector"):
        validate_feature_vector(bad_vector)


# ============================================================================
# REQUIREMENT G: NON-FINITE VALUE HANDLING
# ============================================================================

def test_req_g_non_finite_value_handling():
    # NaN
    vec_nan = np.ones(12)
    vec_nan[3] = np.nan
    with pytest.raises(ValueError, match="Non-finite values detected"):
        validate_feature_vector(vec_nan)

    # +Inf
    vec_inf = np.ones(12)
    vec_inf[7] = np.inf
    with pytest.raises(ValueError, match="Non-finite values detected"):
        validate_feature_vector(vec_inf)

    # -Inf
    vec_neginf = np.ones(12)
    vec_neginf[9] = -np.inf
    with pytest.raises(ValueError, match="Non-finite values detected"):
        validate_feature_vector(vec_neginf)


# ============================================================================
# REQUIREMENT H: CANONICAL MODEL ACCEPTS 12D INPUT
# ============================================================================

def test_req_h_canonical_model_accepts_12d():
    predictor = get_ensemble()
    valid_vec = np.array([
        100.0, 1.0, 1.0, 0.0, 5.0, 2.0, 0.05, 0.01, 50.0, 4.5, 1.0, 1.0
    ])
    res = predictor.score_vector(valid_vec)
    assert 0.0 <= res["final_score"] <= 1.0
    assert 0.0 <= res["rf_score"] <= 1.0
    assert 0.0 <= res["calibrated_if_score"] <= 1.0
    assert res["model_version"] == "v1.0.0-canonical-12d"


# ============================================================================
# REQUIREMENT I: 6D MODEL REJECTION
# ============================================================================

def test_req_i_6d_model_rejection():
    class Mock6DModel:
        n_features_in_ = 6

    with pytest.raises(ValueError, match="Model Compatibility Violation"):
        validate_model_compatibility(Mock6DModel(), "Mock6DModel")

    # Inspect physical checkpoint if available
    path_6d = "backend/ai_engine/model_rf.pkl"
    if os.path.exists(path_6d):
        info = inspect_model_checkpoint(path_6d)
        assert info["detected_dimension"] == 6
        assert info["status"] == STATUS_QUARANTINED


# ============================================================================
# REQUIREMENT J: 13D MODEL REJECTION
# ============================================================================

def test_req_j_13d_model_rejection():
    class Mock13DModel:
        n_features_in_ = 13

    with pytest.raises(ValueError, match="Model Compatibility Violation"):
        validate_model_compatibility(Mock13DModel(), "Mock13DModel")

    path_13d = "backend/ml/evaluation_output/rf_model_unified.pkl"
    if os.path.exists(path_13d):
        info = inspect_model_checkpoint(path_13d)
        assert info["detected_dimension"] == 13
        assert info["status"] == STATUS_QUARANTINED


# ============================================================================
# REQUIREMENT K: 15D MODEL REJECTION
# ============================================================================

def test_req_k_15d_model_rejection():
    class Mock15DModel:
        n_features_in_ = 15

    with pytest.raises(ValueError, match="Model Compatibility Violation"):
        validate_model_compatibility(Mock15DModel(), "Mock15DModel")

    path_15d = "models/isolation_forest_optimized.pkl"
    if os.path.exists(path_15d):
        info = inspect_model_checkpoint(path_15d)
        assert info["detected_dimension"] == 15
        assert info["status"] == STATUS_QUARANTINED


# ============================================================================
# REQUIREMENT L: 32D MODEL REJECTION
# ============================================================================

def test_req_l_32d_model_rejection():
    class Mock32DModel:
        n_features_in_ = 32

    with pytest.raises(ValueError, match="Model Compatibility Violation"):
        validate_model_compatibility(Mock32DModel(), "Mock32DModel")

    path_32d = "ml_models/registry/anomaly_detector.pkl"
    if os.path.exists(path_32d):
        info = inspect_model_checkpoint(path_32d)
        assert info["detected_dimension"] in [32, 33]
        assert info["status"] in [STATUS_QUARANTINED, "LEGACY"]


# ============================================================================
# REQUIREMENT M: NO POSITIONAL TRUNCATION (REJECTS 13D+ INPUTS)
# ============================================================================

def test_req_m_no_positional_truncation():
    # 13D array should be rejected, not truncated to 12D
    arr_13d = np.ones((1, 13))
    with pytest.raises(ValueError, match="Feature dimensionality violation"):
        validate_feature_vector(arr_13d)

    predictor = get_ensemble()
    with pytest.raises(ValueError, match="Feature dimensionality violation"):
        predictor.score_vector(arr_13d)

    with pytest.raises(ValueError, match="Feature dimensionality violation"):
        predictor.predict(arr_13d)


# ============================================================================
# REQUIREMENT N: NO SILENT PADDING (REJECTS <12D INPUTS)
# ============================================================================

def test_req_n_no_silent_padding():
    # 6D array should be rejected, not zero-padded
    arr_6d = np.ones((1, 6))
    with pytest.raises(ValueError, match="Feature dimensionality violation"):
        validate_feature_vector(arr_6d)

    predictor = get_ensemble()
    with pytest.raises(ValueError, match="Feature dimensionality violation"):
        predictor.score_vector(arr_6d)


# ============================================================================
# REQUIREMENT O: API / SERVICE CANONICAL SCHEMA CONSISTENCY
# ============================================================================

def test_req_o_api_and_service_consistency():
    inp = ThreatInput(
        src_ip="192.168.10.50",
        dst_ip="10.0.0.1",
        dst_port=22,
        protocol="TCP",
        length=84,
        threat_score=0.0,
        is_malicious=False,
    )
    # Direct service call
    resp = score_threat(inp)

    # Manual extraction and scoring through canonical ensemble
    extractor = FeatureExtractor()
    extracted_features = extractor.extract_features(inp.model_dump())
    df_feat = pd.DataFrame([extracted_features], columns=CANONICAL_FEATURE_NAMES)
    predictor = get_ensemble()
    scored = predictor.score_vector(df_feat)

    assert np.isclose(resp.score, round(scored["final_score"], 2), atol=1e-2)
    assert resp.threat_level == predictor.classify_severity(scored["final_score"])
    assert resp.decision == predictor.classify_decision(scored["final_score"])


# ============================================================================
# REQUIREMENT P: DETERMINISTIC FEATURE ORDERING
# ============================================================================

def test_req_p_deterministic_feature_ordering():
    event = {
        "src_ip": "172.16.0.4",
        "dst_ip": "192.168.1.100",
        "dst_port": 443,
        "protocol": "TCP",
        "length": 512,
        "raw_data": "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "timestamp": "2026-10-02T10:00:00Z",
    }
    extractor1 = FeatureExtractor()
    extractor2 = FeatureExtractor()
    vec1 = extractor1.extract_vector(event)
    vec2 = extractor2.extract_vector(event)
    assert vec1 == vec2

    # Verify keys strictly match canonical tuple order
    feat_dict1 = extractor1.extract_features(event)
    ordered_keys = list(feat_dict1.keys())
    assert ordered_keys == list(CANONICAL_FEATURE_NAMES)


# ============================================================================
# REQUIREMENT Q: MODEL METADATA / SCHEMA MISMATCH REJECTION
# ============================================================================

def test_req_q_model_metadata_mismatch_rejection():
    # 12-dimensional model, but with host/command feature names
    class MockHost12DModel:
        n_features_in_ = 12
        feature_names_in_ = np.array([
            "command_count", "avg_command_length", "shell_escape_count",
            "directory_traversal_count", "failed_login_count", "payload_entropy",
            "interaction_interval_var", "persistence_score", "ua_diversity",
            "lateral_movement_index", "sensitive_file_count", "payload_to_cmd_ratio"
        ])

    with pytest.raises(ValueError, match="Model Schema Mismatch"):
        validate_model_compatibility(MockHost12DModel(), "MockHost12DModel")

    # Real checkpoint verification
    host_scaler_path = "backend/ml/models/feature_scaler_v2.pkl"
    if os.path.exists(host_scaler_path):
        info = inspect_model_checkpoint(host_scaler_path)
        assert info["detected_dimension"] == 12
        assert info["status"] == STATUS_QUARANTINED
        assert "mismatch" in info["recommended_disposition"]
