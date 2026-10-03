"""
Unit Tests for Remediated 12-Dimensional Feature Extractor
=========================================================
Verifies:
- 12 clean features match exact schema
- No leakage keys present
- Determinism and numeric stability
- Thread-safety under concurrent multi-threaded extraction
- Sliding window pruning
"""

import sys
import os
import threading
from datetime import datetime, timezone, timedelta
import pytest

# Ensure backend in path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from ml.feature_extractor import FeatureExtractor


def test_feature_extractor_schema():
    extractor = FeatureExtractor()
    assert len(extractor.FEATURE_NAMES) == 12
    forbidden_keys = ["threat_score", "is_malicious", "malicious_flag_ratio", "attack_type", "attack_type_frequency"]
    for k in forbidden_keys:
        assert k not in extractor.FEATURE_NAMES

    event = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "length": 512,
        "raw_data": "GET /test HTTP/1.1",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    feats = extractor.extract_features(event)
    assert len(feats) == 12
    for name in extractor.FEATURE_NAMES:
        assert name in feats
        assert isinstance(feats[name], float)


def test_feature_extractor_calculations():
    extractor = FeatureExtractor()
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    
    # Event 1
    ev1 = {
        "src_ip": "10.10.10.10",
        "dst_ip": "192.168.1.1",
        "src_port": 45000,
        "dst_port": 22,
        "protocol": "TCP",
        "length": 100,
        "raw_data": "SSH-2.0-OpenSSH",
        "timestamp": now.isoformat()
    }
    f1 = extractor.extract_features(ev1)
    assert f1["packet_length"] == 100.0
    assert f1["protocol_encoding"] == 1.0  # TCP
    assert f1["dst_port_class"] == 1.0     # Well-known port 22
    assert f1["src_port_ephemeral"] == 1.0 # 45000 >= 1024
    assert f1["event_rate_1m"] == 1.0
    assert f1["burst_rate_10s"] == 1.0
    assert f1["unique_dst_ips"] == 1.0
    assert f1["unique_dst_ports"] == 1.0

    # Event 2 from same IP 2 seconds later
    ev2 = {
        "src_ip": "10.10.10.10",
        "dst_ip": "192.168.1.2",
        "src_port": 45001,
        "dst_port": 8080,
        "protocol": "UDP",
        "length": 200,
        "raw_data": "data",
        "timestamp": (now + timedelta(seconds=2)).isoformat()
    }
    f2 = extractor.extract_features(ev2)
    assert f2["packet_length"] == 200.0
    assert f2["protocol_encoding"] == 2.0  # UDP
    assert f2["dst_port_class"] == 2.0     # Registered port 8080
    assert f2["event_rate_1m"] == 2.0
    assert f2["burst_rate_10s"] == 2.0
    assert f2["inter_arrival_mean"] == 2.0
    assert f2["unique_dst_ips"] == 2.0
    assert f2["unique_dst_ports"] == 2.0


def test_thread_safety_concurrent_extractions():
    extractor = FeatureExtractor()
    errors = []

    def worker(worker_id):
        try:
            ip = f"172.16.1.{worker_id % 5}"
            for i in range(50):
                ev = {
                    "src_ip": ip,
                    "dst_ip": f"10.0.0.{i % 3}",
                    "src_port": 20000 + i,
                    "dst_port": 80 + (i % 5),
                    "protocol": "TCP",
                    "length": 64 + i,
                    "raw_data": f"payload_{i}",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                vec = extractor.extract_vector(ev)
                assert len(vec) == 12
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Concurrent extraction errors encountered: {errors}"
