import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import pytest
from unittest.mock import patch, MagicMock
from schemas.threat_schema import ThreatInput, ThreatResponse
import ml.threat_scoring_service as tss
import pandas as pd

@pytest.fixture
def mock_feature_extractor():
    with patch('ml.threat_scoring_service._FEATURE_EXTRACTOR') as mock_extractor:
        from ml.feature_extractor import FeatureExtractor
        mock_extractor.FEATURE_NAMES = FeatureExtractor.FEATURE_NAMES
        mock_extractor.extract_features.return_value = {k: 0.0 for k in FeatureExtractor.FEATURE_NAMES}
        yield mock_extractor

class MockEnsemble:
    def __init__(self, score=0.8, confidence=0.8):
        self.score = score
        self.confidence = confidence

    def score_vector(self, X_df):
        return {
            "final_score": self.score,
            "confidence": self.confidence,
            "rf_score": self.score,
            "raw_if_score": 0.5,
            "calibrated_if_score": self.score,
            "model_version": "v1.0.0",
        }

    def predict_batch(self, X_df):
        n = len(X_df)
        return pd.DataFrame({
            "ensemble_score": [self.score] * n,
            "rf_prob": [self.score] * n,
            "if_score": [self.score] * n,
            "raw_if_score": [0.5] * n,
        })

@pytest.fixture(autouse=True)
def clear_local_cache():
    """Clears the local prediction cache in the scoring service before each test."""
    tss._LOCAL_PRED_CACHE.clear()
    yield

@pytest.fixture
def mock_redis():
    with patch('ml.threat_scoring_service.REDIS_AVAILABLE', False):
        yield

@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_map_score_to_level_static():
    assert tss.map_score_to_level(0.1) == "LOW"
    assert tss.map_score_to_level(0.5) == "MEDIUM"
    assert tss.map_score_to_level(0.7) == "HIGH"
    assert tss.map_score_to_level(0.85) == "CRITICAL"

@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_map_score_to_level_dynamic_night():
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100,
        timestamp="2026-03-14T03:00:00Z" # Night time UTC
    )
    # Night shifts thresholds down by 0.1 (high shifts from 0.8 to 0.7)
    assert tss.map_score_to_level(0.75, input_data) == "CRITICAL"
    assert tss.map_score_to_level(0.55, input_data) == "HIGH" 

@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_map_score_to_level_dynamic_honeypot():
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=22, protocol="TCP", length=100,
        honeypot_type="SSH"
    )
    # Honeypot shifts thresholds down by 0.15 (high shifts from 0.80 to 0.65)
    assert tss.map_score_to_level(0.50, input_data) == "HIGH"
    assert tss.map_score_to_level(0.70, input_data) == "CRITICAL"

@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_map_score_to_level_dynamic_reputation():
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100,
        is_malicious=True
    )
    # Malicious reputation is an automatic CRITICAL
    assert tss.map_score_to_level(0.1, input_data) == "CRITICAL"

@patch('ml.threat_scoring_service._get_active_ensemble')
@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_score_threat_predict_proba(mock_get_ensemble):
    mock_get_ensemble.return_value = MockEnsemble(score=0.7, confidence=0.7)
    
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100
    )
    
    response = tss.score_threat(input_data)
    
    assert response.score == 0.7
    assert response.threat_level == "HIGH"
    assert response.confidence == 0.7
    assert response.decision == "ALERT"

@patch('ml.threat_scoring_service._get_active_ensemble')
@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_score_threat_predict(mock_get_ensemble):
    mock_get_ensemble.return_value = MockEnsemble(score=0.85, confidence=0.85)
    
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100
    )
    
    response = tss.score_threat(input_data)
    
    assert response.score == 0.85
    assert response.threat_level == "CRITICAL"
    assert response.confidence == 0.85
    assert response.decision == "BLOCK"

@patch('ml.threat_scoring_service._get_active_ensemble')
@pytest.mark.usefixtures("mock_redis")
def test_score_threat_no_model(mock_get_ensemble):
    mock_get_ensemble.return_value = None
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100
    )
    response = tss.score_threat(input_data)
    
    assert response.score == 0.0
    assert response.threat_level == "LOW"
    assert response.decision == "ALLOW"

@patch('ml.threat_scoring_service._get_active_ensemble')
@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_score_threat_batch(mock_get_ensemble):
    mock_get_ensemble.return_value = MockEnsemble(score=0.85, confidence=0.85)
    
    inputs = [
        ThreatInput(src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100),
        ThreatInput(src_ip="1.1.1.2", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=200)
    ]
    
    responses = tss.score_threat_batch(inputs)
    
    assert len(responses) == 2
    for response in responses:
        assert response.score == 0.85
        assert response.threat_level == "CRITICAL"
        assert response.decision == "BLOCK"
