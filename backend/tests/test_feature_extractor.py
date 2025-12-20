import pytest
import sys
import os

# Allow importing from the parent directory (services)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.feature_extractor import FeatureExtractor

@pytest.fixture
def extractor():
    return FeatureExtractor()

def test_time_extraction(extractor):
    # Test valid time difference
    start = "2025-12-20 10:00:00"
    end = "2025-12-20 10:00:10"
    duration = extractor.extract_time_features(start, end)
    assert duration == 10.0

def test_protocol_encoding_tcp(extractor):
    # TCP should be [1, 0, 0]
    assert extractor.encode_protocol("TCP") == [1, 0, 0]

def test_protocol_encoding_udp(extractor):
    # UDP should be [0, 1, 0]
    assert extractor.encode_protocol("UDP") == [0, 1, 0]

def test_ip_patterns(extractor):
    # Test internal IP detection
    patterns = extractor.extract_ip_patterns("192.168.1.5", "192.168.1.10")
    # Expecting [is_internal, is_same_subnet]
    assert patterns[0] == 1  # Both are private IPs
    assert patterns[1] == 1  # Same subnet

def test_normalization(extractor):
    # If max duration is 3600, 1800 should be 0.5
    val = extractor.normalize(1800, 'duration')
    assert val == 0.5

def test_malformed_data(extractor):
    # Should handle garbage dates without crashing
    duration = extractor.extract_time_features("garbage", "data")
    assert duration == 0.0