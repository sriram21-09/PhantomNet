from datetime import datetime, timedelta
from backend.ml.feature_extractor import FeatureExtractor


def sample_event(**overrides):
    base = {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 54321,
        "dst_port": 22,
        "protocol": "TCP",
        "length": 128,
        "payload": "SSH-2.0-OpenSSH_8.2p1",
        "timestamp": datetime.utcnow().isoformat(),
        "honeypot_type": "ssh",
        "is_malicious": True,
    }
    base.update(overrides)
    return base


def test_extract_features_basic():
    extractor = FeatureExtractor()

    event = sample_event()
    features = extractor.extract_features(event)

    # Ensure all canonical 12 features exist
    assert isinstance(features, dict)
    assert len(features) == 12

    expected_keys = {
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

    assert set(features.keys()) == expected_keys


def test_streaming_event_rate_and_unique_destinations():
    extractor = FeatureExtractor()

    event1 = sample_event(dst_ip="192.168.1.20", dst_port=22)
    event2 = sample_event(dst_ip="192.168.1.30", dst_port=80)

    extractor.extract_features(event1)
    features = extractor.extract_features(event2)

    # 2 events from same src_ip within sliding window
    assert features["event_rate_1m"] == 2.0
    assert features["unique_dst_ips"] == 2.0
    assert features["unique_dst_ports"] == 2.0


def test_packet_size_variance_and_entropy():
    extractor = FeatureExtractor()

    extractor.extract_features(sample_event(length=100, payload="AAAA"))
    extractor.extract_features(sample_event(length=200, payload="BBBB"))
    features = extractor.extract_features(sample_event(length=300, payload="ABCD1234!@#$"))

    assert features["packet_size_variance"] > 0
    assert features["payload_entropy"] > 0
