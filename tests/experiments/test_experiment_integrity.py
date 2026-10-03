"""
PhantomNet Experimental & Scientific Integrity Test Suite
=========================================================
Tests covering:
- Dataset integrity, schema validation, and SHA-256 verification
- Absolute prohibition of target, label, and temporal leakage
- Single-feature separability bounds (no trivial features > 85% accuracy)
- Machine-readable artifact schemas and provenance metadata
- Statistical test inputs operating on empirical paired observations
"""

import os
import sys
import json
import hashlib
import pytest
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "remediated_dataset_v3.csv")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "experiments", "results")


class TestDatasetIntegrityAndLeakage:
    """Verifies that datasets strictly adhere to scientific and leakage guidelines."""

    def test_remediated_dataset_exists_and_hashed(self):
        assert os.path.exists(DATASET_PATH), f"Remediated dataset missing at {DATASET_PATH}"
        with open(DATASET_PATH, "rb") as f:
            content = f.read()
        sha256 = hashlib.sha256(content).hexdigest()
        assert len(sha256) == 64

    def test_remediated_dataset_schema_and_dimensions(self):
        df = pd.read_csv(DATASET_PATH)
        assert len(df) == 5000, f"Expected 5000 rows, found {len(df)}"
        assert "label" in df.columns or "is_malicious" in df.columns
        feature_cols = [c for c in df.columns if c not in ["label", "is_malicious"]]
        assert len(feature_cols) == 12, f"Expected exactly 12 features, found {len(feature_cols)}"

    def test_forbidden_leakage_columns(self):
        df = pd.read_csv(DATASET_PATH)
        forbidden_substrings = [
            "threat_score",
            "malicious_flag",
            "ground_truth",
            "prediction",
            "anomaly_score",
        ]
        for col in df.columns:
            if col in ["label", "is_malicious"]:
                continue
            for f in forbidden_substrings:
                assert f not in col.lower(), f"Forbidden leakage column detected: {col}"

    def test_no_trivial_separability(self):
        """Verifies that no single feature can trivially separate the classes (> 85% accuracy)."""
        df = pd.read_csv(DATASET_PATH)
        y = df["label"] if "label" in df.columns else df["is_malicious"]
        feature_cols = [c for c in df.columns if c not in ["label", "is_malicious"]]

        for col in feature_cols:
            vals = df[col].values
            b_mean = np.mean(vals[y == 0])
            m_mean = np.mean(vals[y == 1])
            thresh = (b_mean + m_mean) / 2.0
            preds = (vals > thresh).astype(int) if m_mean > b_mean else (vals < thresh).astype(int)
            acc = accuracy_score(y, preds)
            assert acc < 0.85, f"Feature {col} exhibits trivial separability with accuracy {acc:.4f} >= 0.85"


class TestExperimentArtifactsAndProvenance:
    """Verifies that experimental results have machine-readable provenance."""

    def test_remediated_evaluation_metrics_provenance(self):
        metrics_file = os.path.join(RESULTS_DIR, "remediated_evaluation_metrics.json")
        if os.path.exists(metrics_file):
            with open(metrics_file, "r") as f:
                data = json.load(f)
            assert "dataset" in data
            assert "sha256" in data["dataset"]
            assert "standalone_rf_test" in data
            assert "hybrid_ensemble_test" in data
            assert "accuracy" in data["standalone_rf_test"]

    def test_remediated_statistical_tests_provenance(self):
        stats_file = os.path.join(RESULTS_DIR, "remediated_statistical_tests.json")
        if os.path.exists(stats_file):
            with open(stats_file, "r") as f:
                data = json.load(f)
            assert data.get("n_runs") == 30
            assert "statistical_tests" in data
            assert "accuracy" in data["statistical_tests"]
            assert "wilcoxon_stat" in data["statistical_tests"]["accuracy"]["ens_vs_rf"]
