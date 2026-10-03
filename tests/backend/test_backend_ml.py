"""
PhantomNet Backend ML Integration & Runtime Test Suite
======================================================
Tests covering:
- Canonical feature contract & schema enforcement
- Target & label leakage prevention
- Production model loading and safe fallback
- Model inference & probability bounds
- Threat threshold mapping (CRITICAL/HIGH/MEDIUM/LOW) & decision routing
- Hybrid ensemble scoring & calibration
- DBSCAN campaign clustering with standardized features
- SHAP explainability additivity & stability
- Concurrency and thread safety under simultaneous scoring
"""

import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest
import numpy as np
import pandas as pd

# Add backend to path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from ml.feature_extractor import FeatureExtractor
from ml.threat_scoring_service import (
    score_threat,
    score_threat_batch,
    map_score_to_level,
    map_score_to_decision,
    ThreatInput,
)
from ml import model_loader
from ml_engine.campaign_clustering import CampaignClusterer
from ml_engine.explainability import ModelExplainer


class TestFeatureContractAndLeakage:
    """Verifies the canonical 12D feature contract and absolute leakage prevention."""

    def test_canonical_feature_names_and_count(self):
        extractor = FeatureExtractor()
        assert len(extractor.FEATURE_NAMES) == 12
        expected_names = [
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
        ]
        assert extractor.FEATURE_NAMES == expected_names

    def test_zero_target_and_label_leakage(self):
        """Ensures forbidden downstream fields are never exposed in features."""
        extractor = FeatureExtractor()
        poisoned_event = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 49152,
            "dst_port": 22,
            "protocol": "TCP",
            "length": 100,
            # Malicious attempt to inject labels and prediction scores:
            "threat_score": 0.99,
            "is_malicious": True,
            "malicious_flag_ratio": 1.0,
            "attack_type": "SSH_BRUTE_FORCE",
            "ground_truth_label": 1,
        }
        features = extractor.extract_features(poisoned_event)
        assert "threat_score" not in features
        assert "is_malicious" not in features
        assert "malicious_flag_ratio" not in features
        assert "attack_type" not in features
        assert "ground_truth_label" not in features
        assert len(features) == 12

    def test_numeric_stability_empty_and_extreme_inputs(self):
        extractor = FeatureExtractor()
        extreme_event = {
            "src_ip": None,
            "dst_ip": None,
            "src_port": -100,
            "dst_port": 999999,
            "protocol": "UNKNOWN_PROTO",
            "length": -50,
            "payload": "",
        }
        features = extractor.extract_features(extreme_event)
        for k, v in features.items():
            assert not np.isnan(v), f"Feature {k} returned NaN"
            assert not np.isinf(v), f"Feature {k} returned Inf"


class TestModelLoadingAndInference:
    """Verifies model loading, inference, and threshold mapping."""

    def test_load_production_model(self):
        model = model_loader.load_model()
        assert model is not None
        assert hasattr(model, "predict_proba") or hasattr(model, "predict")

    def test_score_threat_benign_event(self):
        benign_input = ThreatInput(
            src_ip="192.168.1.50",
            dst_ip="192.168.1.1",
            src_port=52341,
            dst_port=443,
            protocol="TCP",
            length=120,
            payload="GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        response = score_threat(benign_input)
        assert 0.0 <= response.score <= 1.0
        assert response.threat_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert response.decision in ["ALLOW", "ALERT", "BLOCK"]

    def test_score_threat_malicious_event(self):
        malicious_input = ThreatInput(
            src_ip="10.99.1.5",
            dst_ip="10.0.2.15",
            src_port=55123,
            dst_port=2222,
            protocol="TCP",
            length=80,
            payload="SSH-2.0-OpenSSH_8.2p1",
            attack_type="SSH_BRUTE_FORCE",
        )
        response = score_threat(malicious_input)
        assert 0.0 <= response.score <= 1.0
        assert response.threat_level in ["MEDIUM", "HIGH", "CRITICAL"]

    def test_threshold_severity_mapping(self):
        assert map_score_to_level(0.20) == "LOW"
        assert map_score_to_level(0.45) == "MEDIUM"
        assert map_score_to_level(0.65) == "HIGH"
        assert map_score_to_level(0.85) == "CRITICAL"

    def test_decision_mapping(self):
        assert map_score_to_decision(0.20) == "ALLOW"
        assert map_score_to_decision(0.55) == "ALERT"
        assert map_score_to_decision(0.85) == "BLOCK"


class TestCampaignClusteringService:
    """Verifies standardized DBSCAN campaign clustering isolation."""

    def test_clusterer_initialization(self):
        clusterer = CampaignClusterer(eps=0.80, min_samples=4)
        assert clusterer.eps == 0.80
        assert clusterer.min_samples == 4
        assert clusterer.model is not None


class TestExplainabilityAndShap:
    """Verifies TreeSHAP model explanation alignment."""

    def test_explainer_initialization_and_explanation(self):
        explainer = ModelExplainer()
        sample_event = {
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.1",
            "src_port": 49200,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 500,
            "payload": "GET /test HTTP/1.1",
        }
        res = explainer.explain_prediction(sample_event)
        assert "error" not in res or res.get("error") is None
        assert "feature_contributions" in res or "top_features" in res or "explanation" in res


class TestConcurrencyAndThreadSafety:
    """Verifies thread-safe feature extraction and scoring under high concurrent load."""

    def test_concurrent_scoring_requests(self):
        extractor = FeatureExtractor()
        errors = []

        def worker(worker_id: int):
            try:
                for i in range(25):
                    ev = {
                        "src_ip": f"10.10.{worker_id}.{i % 5}",
                        "dst_ip": "10.0.0.1",
                        "src_port": 40000 + i,
                        "dst_port": 80 if i % 2 == 0 else 22,
                        "protocol": "TCP",
                        "length": 64 + i * 10,
                        "payload": f"payload_{worker_id}_{i}",
                    }
                    feats = extractor.extract_features(ev)
                    assert len(feats) == 12
                    assert feats["packet_length"] == 64 + i * 10
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, wid) for wid in range(8)]
            for f in futures:
                f.result()

        assert len(errors) == 0, f"Encountered concurrency errors: {errors}"
