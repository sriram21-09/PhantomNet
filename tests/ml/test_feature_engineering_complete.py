import pytest
from datetime import datetime, timezone
import time
import math
from backend.ml.feature_engineering_complete import CompleteFeatureExtractor

def test_extract_all_32_features():
    extractor = CompleteFeatureExtractor()
    event = {
        "src_ip": "1.2.3.4",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "length": 500,
        "protocol": "TCP",
        "raw_data": 'GET /etc/passwd HTTP/1.1\\nUser-Agent: curl/7.68.0',
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "http_request",
        "is_malicious": True,
        "threat_score": 85.0
    }
    
    features = extractor.extract_features(event)
    assert len(features) >= 32, f"Expected 32+ features, got {len(features)}"
    
    # Verify no NaN or infinite values
    for k, v in features.items():
        assert not math.isnan(v), f"Feature {k} is NaN"
        assert not math.isinf(v), f"Feature {k} is Infinite"
        assert isinstance(v, float), f"Feature {k} is not a float"

def test_session_based_features():
    extractor = CompleteFeatureExtractor()
    # Send multiple events from same IP
    for i in range(5):
        event = {
            "src_ip": "1.2.3.4",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dst_port": 80 + i,
            "length": 100 * (i + 1)
        }
        features = extractor.extract_features(event)
        time.sleep(0.01) # artificial delay to test session duration
        
    assert features["unique_port_count"] == 5.0
    assert features["session_duration_estimate"] >= 0.0

def test_behavioral_features():
    extractor = CompleteFeatureExtractor()
    event = {
        "src_ip": "10.0.0.5",
        "raw_data": "/bin/sh -c 'cat /etc/passwd; echo hello'",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    features = extractor.extract_features(event)
    assert features["command_count"] > 0
    assert features["sensitive_file_count"] > 0
    assert features["shell_escape_count"] > 0

def test_feature_normalization():
    extractor = CompleteFeatureExtractor()
    event = {
        "src_ip": "10.0.0.5",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    features = extractor.extract_features(event)
    # Ensure all values are numerical (floats)
    for v in features.values():
        assert isinstance(v, float)

def test_feature_extraction_performance():
    extractor = CompleteFeatureExtractor()
    event = {
        "src_ip": "1.2.3.4",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": "sample payload data"
    }
    
    # Warmup
    extractor.extract_features(event)
    
    start_time = time.time()
    iterations = 100
    for _ in range(iterations):
        extractor.extract_features(event)
    end_time = time.time()
    
    avg_time_ms = ((end_time - start_time) / iterations) * 1000
    assert avg_time_ms < 100, f"Extraction took {avg_time_ms}ms, which exceeds 100ms threshold"

def test_feature_consistency():
    extractor1 = CompleteFeatureExtractor()
    event = {
        "src_ip": "1.2.3.4",
        "timestamp": "2026-03-18T10:00:00+00:00",
        "length": 256
    }
    features1 = extractor1.extract_features(event)
    
    extractor2 = CompleteFeatureExtractor()
    features2 = extractor2.extract_features(event)
    
    # Should get exactly the same features for a clean extractor processing the exact same first event
    for k in features1.keys():
        assert features1[k] == features2[k], f"Inconsistent feature {k}: {features1[k]} vs {features2[k]}"

def test_edge_cases():
    extractor = CompleteFeatureExtractor()
    # Missing fields, weird types
    event = {
        "src_ip": None,
        "timestamp": "invalid-timestamp",
        "length": "not-an-int",
        "dst_port": None,
        "threat_score": "high", # invalid type
        "is_malicious": "yes" # invalid type
    }
    try:
        features = extractor.extract_features(event)
        for k, v in features.items():
            assert isinstance(v, float), f"Expected float for {k}, got {type(v)}"
            assert not math.isnan(v)
            assert not math.isinf(v)
    except Exception as e:
        pytest.fail(f"Failed to handle edge case event: {e}")
