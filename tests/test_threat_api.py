import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from backend.main import app
from backend.schemas.threat_schema import ThreatInput

client = TestClient(app)

# Helper to create valid payload
def get_valid_payload():
    return {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "dst_port": 80,
        "protocol": "TCP",
        "length": 512
    }

@pytest.fixture
def mock_model():
    """Mocks the ML model loader to return a mock sklearn model"""
    with patch("backend.ml.model_loader.load_model") as mock_load:
        mock_sklearn = MagicMock()
        # Setup predict_proba to return 85% malicious (index 1)
        mock_sklearn.predict_proba.return_value = [[0.15, 0.85]]
        mock_load.return_value = mock_sklearn
        yield mock_sklearn

@pytest.fixture
def mock_model_benign():
    """Mocks the ML model for benign traffic"""
    with patch("backend.ml.model_loader.load_model") as mock_load:
        mock_sklearn = MagicMock()
        # Setup predict_proba to return 20% malicious
        mock_sklearn.predict_proba.return_value = [[0.80, 0.20]]
        mock_load.return_value = mock_sklearn
        yield mock_sklearn

@pytest.fixture
def mock_no_model():
    """Mocks missing model scenario"""
    with patch("backend.ml.model_loader.load_model") as mock_load:
        mock_load.return_value = None
        yield mock_load

# ----------------------------------------------------------------
# TESTS
# ----------------------------------------------------------------

def test_analyze_threat_valid_malicious(mock_model):
    """Test standard malicious payload returns HIGH threat"""
    payload = get_valid_payload()
    response = client.post("/api/v1/analyze/threat-score", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["score"] == 85.0
    assert data["threat_level"] == "HIGH"
    assert data["decision"] == "BLOCK"
    assert data["confidence"] == 0.85

def test_analyze_threat_valid_benign(mock_model_benign):
    """Test standard benign payload returns LOW threat"""
    payload = get_valid_payload()
    response = client.post("/api/v1/analyze/threat-score", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["score"] == 20.0
    assert data["threat_level"] == "LOW"
    assert data["decision"] == "ALLOW"

def test_analyze_threat_validation_error():
    """Test missing required field (length)"""
    payload = get_valid_payload()
    del payload["length"]
    
    response = client.post("/api/v1/analyze/threat-score", json=payload)
    assert response.status_code == 422

def test_analyze_threat_invalid_type():
    """Test invalid data type (string for int)"""
    payload = get_valid_payload()
    payload["dst_port"] = "not-a-port"
    
    response = client.post("/api/v1/analyze/threat-score", json=payload)
    assert response.status_code == 422

def test_model_unavailable(mock_no_model):
    """Test 503 when model cannot be loaded"""
    payload = get_valid_payload()
    response = client.post("/api/v1/analyze/threat-score", json=payload)
    
    assert response.status_code == 503
    assert "not available" in response.json()["detail"]
