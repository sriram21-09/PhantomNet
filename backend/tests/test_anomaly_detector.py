import pytest
import os
from backend.ml.anomaly_detector import AnomalyDetector

@pytest.fixture
def detector():
    # Remove old model to ensure fresh test
    if os.path.exists("backend/ml/model.pkl"):
        try:
            os.remove("backend/ml/model.pkl")
        except PermissionError:
            pass # Ignore if file is locked
    return AnomalyDetector()

def test_training_flow(detector):
    """Test that the model can ingest logs and produce a file."""
    # Create fake normal traffic
    normal_logs = [
        {"attacker_ip": "192.168.1.5", "timestamp": "2023-01-01T12:00:00", "status": "Success"}
        for _ in range(50)
    ]
    
    # Train
    detector.train(normal_logs)
    
    # Check if model saved
    assert detector.is_trained == True
    assert os.path.exists("backend/ml/model.pkl")

def test_detection(detector):
    """Test that it can predict on new data."""
    # Ensure it's trained first
    # Create fake logs to train quickly
    logs = [{"attacker_ip": "1.1.1.1", "timestamp": "2023-01-01"} for _ in range(20)]
    detector.train(logs)
    
    # Normal looking log
    normal_log = {"attacker_ip": "192.168.1.5", "timestamp": "2023-01-01T12:05:00", "status": "Success"}
    pred, score = detector.predict(normal_log)
    
    # Isolation Forest outputs: 1 (Normal), -1 (Anomaly)
    assert pred in [1, -1]
    assert isinstance(score, float)