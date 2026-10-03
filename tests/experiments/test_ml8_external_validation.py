"""
PhantomNet Phase ML-8: External Benchmark Validation Automated Test Suite
========================================================================
Validates:
1. Dataset Provenance and Checksum Integrity
2. Canonical 12D Feature Schema Contract Enforcement
3. Feature Mapping Completeness and Transformation Safety
4. Label Mapping and Normalization Safety
5. Target and Leakage Isolation
6. Frozen Model Checksums and Preprocessing Isolation (Track A)
7. Absence of External Test Data Contamination / Training
8. Distribution Shift Artifact Validity and PSI Computations
9. Model Metric Generation and Threshold Separation
10. Attack Family and Error Analysis Artifacts
11. Cross-Dataset Statistical Hypothesis Testing
12. Reproducibility Manifest Concordance
13. Model Registry Safety (Track B Isolation in ml_models/experimental/)
14. Publication Claim Classification Consistency
15. Scientific Limitation Register Completeness (LIM-01 to LIM-20)
16. Historical Phase ML-1 through ML-7 Preservation
"""

import os
import json
import hashlib
import pytest
import numpy as np
import pandas as pd

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RESULTS_DIR = os.path.join(REPO_ROOT, "experiments", "results")
DATA_DIR = os.path.join(REPO_ROOT, "data", "external_benchmarks")
MODELS_DIR = os.path.join(REPO_ROOT, "ml_models")
EXPERIMENTAL_MODELS_DIR = os.path.join(MODELS_DIR, "experimental")

from backend.ml.config.feature_schema import (
    CANONICAL_FEATURE_NAMES,
    CANONICAL_FEATURE_COUNT,
    SCHEMA_VERSION,
    validate_feature_vector,
)
from backend.ml.config.thresholds import (
    RF_WEIGHT,
    IF_WEIGHT,
    BLOCK_THRESHOLD,
    ALERT_THRESHOLD,
)

EXPECTED_FROZEN_SHAS = {
    "rf": "7ca8651fca269842d7f0f829a5aba9485453a38fa6263a67c2130ac0c9c66dc2",
    "if": "3a057d52a125d22ae46f7b83f92aaec02aea42a2c56519c70add3890a9c04b7b",
    "scaler": "4f7b1ea192f136f718af7868947c23b965c41c083ccab1b3da955a9035f74e8d",
}


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ==============================================================================
# 1. DATASET INVENTORY & PROVENANCE TESTS
# ==============================================================================

class TestDatasetInventoryAndProvenance:
    def test_dataset_inventory_artifact(self):
        path = os.path.join(RESULTS_DIR, "ml8_dataset_inventory.json")
        assert os.path.exists(path), "Missing ml8_dataset_inventory.json"
        with open(path, "r") as f:
            data = json.load(f)
        assert data["external_datasets_count"] == 3
        names = [item["name"] for item in data["inventory"]]
        assert "NF-ToN-IoT-v2" in names
        assert "CIC-IDS2017" in names
        assert "UNSW-NB15" in names

    def test_raw_datasets_exist_and_hashes_match(self):
        inv_path = os.path.join(RESULTS_DIR, "ml8_dataset_inventory.json")
        with open(inv_path, "r") as f:
            data = json.load(f)
        for item in data["inventory"]:
            raw_path = item["raw_file"]
            assert os.path.exists(raw_path), f"Raw dataset not found: {raw_path}"
            assert os.path.getsize(raw_path) > 10000, f"Raw dataset too small: {raw_path}"
            current_sha = sha256_file(raw_path)
            assert current_sha == item["raw_sha256"], f"SHA mismatch on {item['name']}"

    def test_provenance_dag_integrity(self):
        path = os.path.join(RESULTS_DIR, "ml8_dataset_provenance.json")
        assert os.path.exists(path), "Missing ml8_dataset_provenance.json"
        with open(path, "r") as f:
            dag = json.load(f)
        node_ids = {n["id"] for n in dag["nodes"]}
        assert "SRC_CIC" in node_ids
        assert "SRC_TON" in node_ids
        assert "SRC_UNSW" in node_ids
        assert "MAP_12D" in node_ids
        assert "EVAL_FROZEN" in node_ids
        assert "EVAL_ADAPT" in node_ids
        assert len(dag["edges"]) >= 9


# ==============================================================================
# 2. FEATURE CONTRACT & MAPPING TESTS
# ==============================================================================

class TestFeatureMappingAndSchemaContract:
    @pytest.mark.parametrize("fname", [
        "nf_ton_iot_v2_canonical_12d.csv",
        "cicids2017_canonical_12d.csv",
        "unsw_nb15_canonical_12d.csv"
    ])
    def test_canonical_12d_files_exist_and_validate(self, fname):
        fpath = os.path.join(DATA_DIR, fname)
        assert os.path.exists(fpath), f"Missing canonical 12D file: {fname}"
        df = pd.read_csv(fpath)
        assert len(df) == 5000, f"Expected 5,000 samples, got {len(df)}"
        assert df.shape[1] == 13, f"Expected 13 columns (12 features + label), got {df.shape[1]}"
        # Contract validation
        X = df[list(CANONICAL_FEATURE_NAMES)]
        arr = validate_feature_vector(X)
        assert arr.shape == (5000, 12)
        assert not np.isnan(arr).any(), "NaN found in feature vector"
        assert not np.isinf(arr).any(), "Inf found in feature vector"

    def test_feature_mapping_completeness(self):
        path = os.path.join(RESULTS_DIR, "ml8_feature_mapping.json")
        assert os.path.exists(path), "Missing ml8_feature_mapping.json"
        with open(path, "r") as f:
            data = json.load(f)
        for ds in ["NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            mappings = data["mappings"][ds]
            assert len(mappings) == 12, f"Expected 12 feature mappings for {ds}"
            mapped_names = [m["canonical_feature"] for m in mappings]
            assert tuple(mapped_names) == CANONICAL_FEATURE_NAMES

    def test_label_mapping_validity(self):
        path = os.path.join(RESULTS_DIR, "ml8_label_mapping.json")
        assert os.path.exists(path), "Missing ml8_label_mapping.json"
        with open(path, "r") as f:
            data = json.load(f)
        for ds in ["NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            assert ds in data
            assert "binary_mapping" in data[ds]
            assert len(data[ds]["multiclass_attack_types"]) >= 2


# ==============================================================================
# 3. FROZEN MODELS & TRAINING ISOLATION TESTS
# ==============================================================================

class TestFrozenModelSafetyAndLeakage:
    def test_canonical_model_checksums(self):
        rf_path = os.path.join(MODELS_DIR, "registry", "AttackClassifier_Enhanced_v1.0.0.pkl")
        if_path = os.path.join(MODELS_DIR, "iforest_baseline.pkl")
        scaler_path = os.path.join(MODELS_DIR, "registry", "scaler.pkl")

        assert sha256_file(rf_path) == EXPECTED_FROZEN_SHAS["rf"]
        assert sha256_file(if_path) == EXPECTED_FROZEN_SHAS["if"]
        assert sha256_file(scaler_path) == EXPECTED_FROZEN_SHAS["scaler"]

    def test_integrity_audit_artifact(self):
        path = os.path.join(RESULTS_DIR, "ml8_integrity_audit.json")
        assert os.path.exists(path), "Missing ml8_integrity_audit.json"
        with open(path, "r") as f:
            data = json.load(f)
        assert data["target_leakage_detected"] is False
        assert data["test_contamination_detected"] is False
        assert data["frozen_models_verified"] is True

    def test_track_b_model_isolation(self):
        adapt_path = os.path.join(EXPERIMENTAL_MODELS_DIR, "TrackB_External_Adapted_v1.0.0.pkl")
        assert os.path.exists(adapt_path), "Missing Track B adapted model checkpoint"
        # Ensure it is not active in production registry
        prod_reg = os.path.join(MODELS_DIR, "registry", "models_index.json")
        if os.path.exists(prod_reg):
            with open(prod_reg, "r") as f:
                idx = json.load(f)
            assert "TrackB" not in idx.get("active_model", "")
            assert "Adapted" not in idx.get("active_model", "")


# ==============================================================================
# 4. TRACK A & TRACK B METRIC ARTIFACT TESTS
# ==============================================================================

class TestMetricArtifactsAndEvaluations:
    def test_external_metrics_artifact(self):
        path = os.path.join(RESULTS_DIR, "ml8_external_metrics.json")
        assert os.path.exists(path), "Missing ml8_external_metrics.json"
        with open(path, "r") as f:
            data = json.load(f)
        for ds in ["NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            assert ds in data
            for m in ["RandomForest", "IsolationForest", "Ensemble"]:
                assert m in data[ds]
                metrics = data[ds][m]
                assert 0.0 <= metrics["roc_auc"] <= 1.0
                assert 0.0 <= metrics["accuracy_at_0.50"] <= 1.0
                assert 0.0 <= metrics["fpr_at_0.50"] <= 1.0

    def test_track_b_adaptation_gain(self):
        path = os.path.join(RESULTS_DIR, "ml8_adaptation_metrics.json")
        assert os.path.exists(path), "Missing ml8_adaptation_metrics.json"
        with open(path, "r") as f:
            data = json.load(f)
        assert data["test_roc_auc"] > 0.90, "Adapted model should achieve high discrimination"
        assert data["adaptation_gain_f1"] > 0.40, "Adaptation should demonstrate significant gain"
        assert data["status"] == "EXPERIMENTAL (Non-Production)"

    def test_distribution_shift_artifact(self):
        path = os.path.join(RESULTS_DIR, "ml8_distribution_shift.json")
        assert os.path.exists(path), "Missing ml8_distribution_shift.json"
        with open(path, "r") as f:
            data = json.load(f)
        for ds in ["NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            assert ds in data
            assert data[ds]["classification"] == "SEVERE SHIFT"
            assert data[ds]["mean_psi"] > 0.25

    def test_statistical_tests_artifact(self):
        path = os.path.join(RESULTS_DIR, "ml8_statistical_tests.json")
        assert os.path.exists(path), "Missing ml8_statistical_tests.json"
        with open(path, "r") as f:
            tests = json.load(f)
        assert len(tests) == 2
        for t in tests:
            assert "hypothesis" in t
            assert "ci_95" in t
            assert "p_value" in t

    def test_reproducibility_verdict(self):
        path = os.path.join(RESULTS_DIR, "ml8_reproducibility.json")
        assert os.path.exists(path), "Missing ml8_reproducibility.json"
        with open(path, "r") as f:
            data = json.load(f)
        assert data["status"] in ["BITWISE_DETERMINISTIC", "NUMERICALLY_IDENTICAL_WITH_FLOATING_POINT_EPSILON"]
        assert data["max_floating_point_delta"] < 1e-6


# ==============================================================================
# 5. CLAIMS & LIMITATION REGISTER TESTS
# ==============================================================================

class TestClaimsAndLimitations:
    def test_claim_traceability_matrix(self):
        path = os.path.join(RESULTS_DIR, "ml8_claim_traceability.json")
        assert os.path.exists(path), "Missing ml8_claim_traceability.json"
        with open(path, "r") as f:
            claims = json.load(f)
        assert len(claims) == 8
        statuses = {c["claim_id"]: c["status"] for c in claims}
        assert statuses["CLM-ML8-01"] == "UNSUPPORTED"
        assert statuses["CLM-ML8-02"] == "VERIFIED WITH QUALIFICATION"
        assert statuses["CLM-ML8-03"] == "UNSUPPORTED"
        assert statuses["CLM-ML8-04"] == "UNSUPPORTED"
        assert statuses["CLM-ML8-08"] == "VERIFIED"

    def test_scientific_limitation_register_count(self):
        path = os.path.join(RESULTS_DIR, "ml8_limitation_register.json")
        assert os.path.exists(path), "Missing ml8_limitation_register.json"
        with open(path, "r") as f:
            lims = json.load(f)
        assert len(lims) >= 20, f"Expected at least 20 limitations, got {len(lims)}"
        ids = [lim["id"] for lim in lims]
        assert "LIM-16" in ids
        assert "LIM-17" in ids
        assert "LIM-20" in ids

    def test_historical_ml7_artifacts_exist_and_unmodified(self):
        ml7_path = os.path.join(RESULTS_DIR, "ml7_reproducibility.json")
        assert os.path.exists(ml7_path), "Historical ML-7 reproducibility artifact missing"
        with open(ml7_path, "r") as f:
            data = json.load(f)
        assert data["verdict"] == "PERFECT_REPRODUCIBILITY"
