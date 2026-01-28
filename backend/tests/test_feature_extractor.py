import pytest
import numpy as np
from datetime import datetime, timedelta
from backend.ml.feature_extractor import FeatureExtractor

@pytest.fixture
def extractor():
    return FeatureExtractor()

@pytest.fixture
def sample_log():
    return {
        "timestamp": datetime.now().isoformat(),
        "attacker_ip": "192.168.1.50",
        "target_node": "Server_A",
        "service_type": "SSH",
        "username": "admin",
        "password": "password123",
        "status": "Failed",
        "packet_count": 15,
        "payload_size": 1024,
        "command_count": 3,
        "headers": {"User-Agent": "Mozilla", "Accept": "*/*"},
        "url_count": 2,
        "payload": "SELECT * FROM users; DROP TABLE;" # High entropy SQL injection
    }

def test_vector_dimensions(extractor, sample_log):
    """Ensure we are now extracting exactly 13 features."""
    vector = extractor.extract_features(sample_log)
    # 3 Temporal + 4 Network + 6 Content = 13 Total
    assert len(vector) == 13
    assert isinstance(vector, np.ndarray)

def test_entropy_calculation(extractor):
    """Verify entropy is higher for random strings."""
    # Low entropy (repetitive)
    low_ent = extractor._calculate_entropy("aaaaaa")
    # High entropy (random)
    high_ent = extractor._calculate_entropy("8s7df687s6d")
    
    assert high_ent > low_ent

def test_failed_auth_tracking(extractor):
    """Verify the stateful counter for failed logins."""
    log = {
        "attacker_ip": "10.0.0.1", 
        "timestamp": datetime.now().isoformat(),
        "status": "Failed"
    }
    
    # First failure
    v1 = extractor.extract_features(log)
    # Index 10 is failed_auth_count (based on append order: 3 temp + 4 net + 3 content_skip... let's check value)
    # Actually, simpler to check the tracker directly for unit testing
    assert extractor.failed_auth_tracker["10.0.0.1"] == 1
    
    # Second failure
    extractor.extract_features(log)
    assert extractor.failed_auth_tracker["10.0.0.1"] == 2

def test_geo_mock(extractor):
    """Verify geo score is deterministic."""
    score1 = extractor._get_geo_score("1.1.1.2") # Ends in 2
    score2 = extractor._get_geo_score("1.1.1.2") # Ends in 2
    assert score1 == score2