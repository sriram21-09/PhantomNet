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
        # Mock extract_features to return a simple dictionary matching FEATURE_NAMES
        # We need to know FEATURE_NAMES to mock it properly, but we can just mock the whole flow
        # where the model input is matched by the model mock
        mock_extractor.FEATURE_NAMES = ['feat1', 'feat2']
        mock_extractor.extract_features.return_value = {'feat1': 1.0, 'feat2': 2.0}
        yield mock_extractor

class MockModelPredictProba:
    def predict_proba(self, X):
        # Return probability of [benign, malicious]
        # X is expected to have rows
        return [[0.2, 0.8]] * len(X)

class MockModelPredict:
    def predict(self, X):
        # Return -1 for anomaly, 1 for normal
        return [-1] * len(X)

@pytest.fixture
def mock_redis():
    with patch('ml.threat_scoring_service.REDIS_AVAILABLE', False):
        yield

@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_map_score_to_level_static():
    assert tss.map_score_to_level(10.0) == "LOW"
    assert tss.map_score_to_level(50.0) == "MEDIUM"
    assert tss.map_score_to_level(80.0) == "HIGH"
    assert tss.map_score_to_level(95.0) == "CRITICAL"

@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_map_score_to_level_dynamic_night():
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100,
        timestamp="2026-03-14T03:00:00Z" # Night time UTC
    )
    # Night shifts medium to 65, high to 80
    assert tss.map_score_to_level(66.0, input_data) == "HIGH" # 66 > 65
    assert tss.map_score_to_level(85.0, input_data) == "CRITICAL" # 85 > 80

@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_map_score_to_level_dynamic_honeypot():
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=22, protocol="TCP", length=100,
        honeypot_type="SSH"
    )
    # Honeypot shifts medium to 60, high to 75
    assert tss.map_score_to_level(65.0, input_data) == "HIGH"
    assert tss.map_score_to_level(80.0, input_data) == "CRITICAL"

@pytest.mark.usefixtures("mock_redis", "mock_feature_extractor")
def test_map_score_to_level_dynamic_reputation():
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100,
        is_malicious=True
    )
    # Malicious reputation is an automatic CRITICAL
    assert tss.map_score_to_level(10.0, input_data) == "CRITICAL"

@patch('ml.threat_scoring_service.model_loader.load_model')
@pytest.mark.usefixtures("mock_redis")
def test_score_threat_predict_proba(mock_load_model, mock_feature_extractor):
    mock_load_model.return_value = MockModelPredictProba()
    
    # Needs a real FeatureExtractor FEATURE_NAMES assignment to avoid pandas mismatch
    from ml.feature_extractor import FeatureExtractor
    mock_feature_extractor.FEATURE_NAMES = FeatureExtractor.FEATURE_NAMES
    
    # Just need it to return a dit with correct keys 
    mock_feature_extractor.extract_features.return_value = {k: 0 for k in FeatureExtractor.FEATURE_NAMES}
    
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100
    )
    
    response = tss.score_threat(input_data)
    
    assert response.score == 80.0
    assert response.threat_level == "HIGH"
    assert response.confidence == 0.8
    assert response.decision == "BLOCK"

@patch('ml.threat_scoring_service.model_loader.load_model')
@pytest.mark.usefixtures("mock_redis")
def test_score_threat_predict(mock_load_model, mock_feature_extractor):
    mock_load_model.return_value = MockModelPredict()
    
    from ml.feature_extractor import FeatureExtractor
    mock_feature_extractor.FEATURE_NAMES = FeatureExtractor.FEATURE_NAMES
    mock_feature_extractor.extract_features.return_value = {k: 0 for k in FeatureExtractor.FEATURE_NAMES}
    
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100
    )
    
    response = tss.score_threat(input_data)
    
    assert response.score == 85.0
    assert response.threat_level == "HIGH"
    assert response.confidence == 0.85
    assert response.decision == "BLOCK"

@patch('ml.threat_scoring_service.model_loader.load_model')
@pytest.mark.usefixtures("mock_redis")
def test_score_threat_no_model(mock_load_model):
    mock_load_model.return_value = None
    input_data = ThreatInput(
        src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100
    )
    response = tss.score_threat(input_data)
    
    assert response.score == 0.0
    assert response.threat_level == "LOW"
    assert response.decision == "ALLOW"

@patch('ml.threat_scoring_service.model_loader.load_model')
@pytest.mark.usefixtures("mock_redis")
def test_score_threat_batch(mock_load_model, mock_feature_extractor):
    mock_load_model.return_value = MockModelPredictProba()
    
    from ml.feature_extractor import FeatureExtractor
    mock_feature_extractor.FEATURE_NAMES = FeatureExtractor.FEATURE_NAMES
    mock_feature_extractor.extract_features.side_effect = lambda ev: {k: 0 for k in FeatureExtractor.FEATURE_NAMES}
    
    inputs = [
        ThreatInput(src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=100),
        ThreatInput(src_ip="1.1.1.2", dst_ip="2.2.2.2", dst_port=80, protocol="TCP", length=200)
    ]
    
    responses = tss.score_threat_batch(inputs)
    
    assert len(responses) == 2
    for response in responses:
        assert response.score == 80.0
        assert response.threat_level == "HIGH"
        assert response.decision == "BLOCK"
