from datetime import datetime, timedelta
from backend.ml.feature_extractor import FeatureExtractor


def sample_event(**overrides):
    base = {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "dst_port": 22,
        "protocol": "TCP",
        "length": 128,
        "timestamp": datetime.utcnow().isoformat(),
        "threat_score": 75.0,
        "attack_type": "bruteforce",
        "honeypot_type": "ssh",
        "is_malicious": True,
    }
    base.update(overrides)
    return base


def test_extract_features_basic():
    extractor = FeatureExtractor()

    event = sample_event()
    features = extractor.extract_features(event)

    # Ensure all 15 features exist
    assert isinstance(features, dict)
    assert len(features) == 15

    expected_keys = {
        "packet_length",
        "protocol_encoding",
        "source_ip_event_rate",
        "destination_port_class",
        "threat_score",
        "malicious_flag_ratio",
        "attack_type_frequency",
        "time_of_day_deviation",
        "burst_rate",
        "packet_size_variance",
        "honeypot_interaction_count",
        "session_duration_estimate",
        "unique_destination_count",
        "rolling_average_deviation",
        "z_score_anomaly",
    }

    assert set(features.keys()) == expected_keys


def test_malicious_flag_ratio_computation():
    extractor = FeatureExtractor()

    benign = sample_event(is_malicious=False)
    malicious = sample_event(is_malicious=True)

    extractor.extract_features(benign)
    features = extractor.extract_features(malicious)

    # 1 malicious out of 2 total events
    assert features["malicious_flag_ratio"] == 0.5


def test_session_duration_and_honeypot_count():
    extractor = FeatureExtractor()

    t1 = datetime.utcnow()
    t2 = t1 + timedelta(seconds=120)

    event1 = sample_event(timestamp=t1.isoformat(), honeypot_type="ssh")
    event2 = sample_event(timestamp=t2.isoformat(), honeypot_type="ftp")

    extractor.extract_features(event1)
    features = extractor.extract_features(event2)

    assert features["session_duration_estimate"] >= 120
    assert features["honeypot_interaction_count"] == 2


def test_packet_size_variance_and_zscore():
    extractor = FeatureExtractor()

    extractor.extract_features(sample_event(length=100))
    extractor.extract_features(sample_event(length=200))
    features = extractor.extract_features(sample_event(length=300))

    assert features["packet_size_variance"] > 0
    assert isinstance(features["z_score_anomaly"], float)
