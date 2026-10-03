"""Phase ML-4 Executable Verification Suite.

Tests at minimum:
A. Dataset hash verification
B. Dataset dimensions
C. Canonical feature names/order
D. Target isolation
E. Missing-value integrity
F. Infinite-value integrity
G. Duplicate analysis
H. Conflicting duplicate labels
I. Single-feature leakage screening
J. Train/test preprocessing boundary
K. No target access during extraction
L. Active dataset provenance
M. Legacy dataset quarantine
N. Deterministic generation
O. Reproducible train/test splitting
P. Programmatic metric generation
Q. Programmatic statistical generation
R. Run A / Run B reproducibility
S. No stale active dataset references
"""

import os
import json
import hashlib
import subprocess
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import roc_auc_score, accuracy_score

from backend.ml.config.feature_schema import (
    SCHEMA_VERSION,
    CANONICAL_FEATURE_NAMES,
    CANONICAL_FEATURE_COUNT,
    CANONICAL_TARGET_NAME,
    validate_feature_vector,
)
from backend.ml.feature_extractor import FeatureExtractor


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CANONICAL_DATASET = PROJECT_ROOT / "data" / "remediated_dataset_v3.csv"
BACKEND_DATASET = PROJECT_ROOT / "backend" / "ml" / "datasets" / "labeled_events_remediated.csv"
EXPECTED_SHA256 = "390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363"


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Test A: Dataset hash verification
# ---------------------------------------------------------------------------
def test_req_a_dataset_hash_verification():
    assert CANONICAL_DATASET.exists(), f"Missing dataset: {CANONICAL_DATASET}"
    actual_hash = compute_sha256(CANONICAL_DATASET)
    assert actual_hash == EXPECTED_SHA256, (
        f"Dataset hash mismatch! Expected {EXPECTED_SHA256}, got {actual_hash}"
    )


# ---------------------------------------------------------------------------
# Test B: Dataset dimensions
# ---------------------------------------------------------------------------
def test_req_b_dataset_dimensions():
    df = pd.read_csv(CANONICAL_DATASET)
    assert df.shape == (5000, 13), f"Expected shape (5000, 13), got {df.shape}"
    assert len(df) == 5000
    assert len(df.columns) == 13


# ---------------------------------------------------------------------------
# Test C: Canonical feature names and ordering
# ---------------------------------------------------------------------------
def test_req_c_canonical_feature_names_order():
    df = pd.read_csv(CANONICAL_DATASET)
    cols = list(df.columns)
    feature_cols = cols[:-1]
    target_col = cols[-1]

    assert tuple(feature_cols) == CANONICAL_FEATURE_NAMES, (
        f"Feature order mismatch: {feature_cols} != {CANONICAL_FEATURE_NAMES}"
    )
    assert target_col == CANONICAL_TARGET_NAME


# ---------------------------------------------------------------------------
# Test D: Target isolation
# ---------------------------------------------------------------------------
def test_req_d_target_isolation():
    df = pd.read_csv(CANONICAL_DATASET)
    assert CANONICAL_TARGET_NAME in df.columns
    target_vals = set(df[CANONICAL_TARGET_NAME].unique())
    assert target_vals == {0, 1}, f"Target must be binary {{0, 1}}, got {target_vals}"

    counts = df[CANONICAL_TARGET_NAME].value_counts().to_dict()
    assert counts[0] == 3500, f"Expected 3500 benign, got {counts.get(0)}"
    assert counts[1] == 1500, f"Expected 1500 malicious, got {counts.get(1)}"

    # Ensure no other target columns exist
    leakage_cols = ["threat_score", "is_malicious", "attack_cat", "malicious_flag_ratio"]
    for lcol in leakage_cols:
        assert lcol not in df.columns, f"Forbidden leakage column {lcol} found in dataset!"


# ---------------------------------------------------------------------------
# Test E: Missing-value integrity
# ---------------------------------------------------------------------------
def test_req_e_missing_value_integrity():
    df = pd.read_csv(CANONICAL_DATASET)
    missing = df.isna().sum().sum()
    assert missing == 0, f"Found {missing} missing/NaN values in dataset!"


# ---------------------------------------------------------------------------
# Test F: Infinite-value integrity
# ---------------------------------------------------------------------------
def test_req_f_infinite_value_integrity():
    df = pd.read_csv(CANONICAL_DATASET)
    inf_count = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
    assert inf_count == 0, f"Found {inf_count} infinite values in dataset!"


# ---------------------------------------------------------------------------
# Test G: Duplicate analysis
# ---------------------------------------------------------------------------
def test_req_g_duplicate_analysis():
    df = pd.read_csv(CANONICAL_DATASET)
    full_dups = df.duplicated().sum()
    assert full_dups == 0, f"Found {full_dups} duplicate rows in dataset!"

    X = df.drop(columns=[CANONICAL_TARGET_NAME])
    feature_dups = X.duplicated().sum()
    assert feature_dups == 0, f"Found {feature_dups} duplicate feature vectors in dataset!"


# ---------------------------------------------------------------------------
# Test H: Conflicting duplicate labels
# ---------------------------------------------------------------------------
def test_req_h_conflicting_duplicate_labels():
    df = pd.read_csv(CANONICAL_DATASET)
    X_cols = list(CANONICAL_FEATURE_NAMES)
    conflicts = df.groupby(X_cols)[CANONICAL_TARGET_NAME].nunique()
    conflict_count = (conflicts > 1).sum()
    assert conflict_count == 0, f"Found {conflict_count} conflicting duplicate labels!"


# ---------------------------------------------------------------------------
# Test I: Single-feature leakage screening
# ---------------------------------------------------------------------------
def test_req_i_single_feature_leakage_screening():
    df = pd.read_csv(CANONICAL_DATASET)
    X = df[list(CANONICAL_FEATURE_NAMES)]
    y = df[CANONICAL_TARGET_NAME]

    for col in CANONICAL_FEATURE_NAMES:
        vals = X[[col]]

        # Decision stump accuracy check (must not be trivially separable, acc < 0.85)
        stump = DecisionTreeClassifier(max_depth=1, random_state=42)
        stump.fit(vals, y)
        acc = accuracy_score(y, stump.predict(vals))
        assert acc < 0.85, f"Feature {col} has suspiciously high stump accuracy: {acc:.4f}"

        # Single feature ROC-AUC check (must be < 0.90)
        auc_raw = roc_auc_score(y, X[col])
        auc = max(auc_raw, 1.0 - auc_raw)
        assert auc < 0.90, f"Feature {col} has suspiciously high ROC-AUC: {auc:.4f}"


# ---------------------------------------------------------------------------
# Test J: Train/test preprocessing boundary
# ---------------------------------------------------------------------------
def test_req_j_train_test_preprocessing_boundary():
    df = pd.read_csv(CANONICAL_DATASET)
    X = df[list(CANONICAL_FEATURE_NAMES)]
    y = df[CANONICAL_TARGET_NAME].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=100, stratify=y
    )

    # Prove scaler fits strictly on train, and test does not alter training params
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    train_mean = scaler.mean_.copy()
    train_scale = scaler.scale_.copy()

    X_test_s = scaler.transform(X_test)
    assert np.array_equal(scaler.mean_, train_mean), "Scaler mean was mutated during test transform!"
    assert np.array_equal(scaler.scale_, train_scale), "Scaler scale was mutated during test transform!"

    # Test set transformation must match exact formula using training mean and scale
    expected_test_s = (X_test.values - train_mean) / train_scale
    assert np.allclose(X_test_s, expected_test_s), "Test transform does not match training-fitted parameters!"


# ---------------------------------------------------------------------------
# Test J2: Train/test cross-split overlap detection across all 30 splits
# ---------------------------------------------------------------------------
def test_req_train_test_overlap_detection():
    df = pd.read_csv(CANONICAL_DATASET)
    X = df[list(CANONICAL_FEATURE_NAMES)]
    y = df[CANONICAL_TARGET_NAME].values

    for seed in range(100, 130):
        X_train, X_test, _, _ = train_test_split(
            X, y, test_size=0.20, random_state=seed, stratify=y
        )
        overlap = pd.merge(X_train, X_test, how="inner")
        assert len(overlap) == 0, (
            f"Seed {seed}: Found {len(overlap)} overlapping records between train and test sets!"
        )


# ---------------------------------------------------------------------------
# Test K: No target access during feature extraction
# ---------------------------------------------------------------------------
def test_req_k_no_target_access_during_extraction():
    extractor = FeatureExtractor()
    raw_packet = {
        "length": 512,
        "protocol": 6,
        "src_port": 49152,
        "dst_port": 443,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "payload": b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        # Attack label and threat_score injected
        "label": 1,
        "is_malicious": True,
        "threat_score": 0.95,
    }

    # Extraction must succeed, and output must strictly have 12 features with NO target
    vec_dict = extractor.extract_features(raw_packet)
    assert len(vec_dict) == 12
    for lcol in ["label", "is_malicious", "threat_score", "attack_cat"]:
        assert lcol not in vec_dict

    # Vector conversion must succeed through canonical validation
    vec = extractor.extract_vector(raw_packet)
    assert len(vec) == 12
    assert np.all(np.isfinite(vec))


# ---------------------------------------------------------------------------
# Test L: Active dataset provenance
# ---------------------------------------------------------------------------
def test_req_l_active_dataset_provenance():
    assert CANONICAL_DATASET.exists()
    assert BACKEND_DATASET.exists()

    h_canonical = compute_sha256(CANONICAL_DATASET)
    h_backend = compute_sha256(BACKEND_DATASET)
    assert h_canonical == EXPECTED_SHA256
    assert h_backend == EXPECTED_SHA256, "Backend replica hash does not match canonical dataset!"


# ---------------------------------------------------------------------------
# Test M: Legacy dataset quarantine
# ---------------------------------------------------------------------------
def test_req_m_legacy_dataset_quarantine():
    quarantine_manifest_path = PROJECT_ROOT / "experiments" / "results" / "ml4_dataset_audit.json"
    assert quarantine_manifest_path.exists(), "Missing ml4_dataset_audit.json"

    with open(quarantine_manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    manifest = data.get("legacy_dataset_manifest", [])
    quarantined = [item for item in manifest if item.get("status") == "QUARANTINED"]
    assert len(quarantined) >= 4, f"Expected at least 4 quarantined datasets, got {len(quarantined)}"

    # Ensure training_dataset.csv and labeled_events_v2_enhanced.csv are explicitly quarantined
    paths = [item["path"] for item in quarantined]
    assert "data/training_dataset.csv" in paths
    assert "backend/ml/datasets/labeled_events_v2_enhanced.csv" in paths


# ---------------------------------------------------------------------------
# Test N: Deterministic generation
# ---------------------------------------------------------------------------
def test_req_n_deterministic_generation():
    gen_script = PROJECT_ROOT / "scripts" / "generate_remediated_dataset.py"
    assert gen_script.exists()

    res = subprocess.run(
        ["python", str(gen_script)],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(PROJECT_ROOT),
    )
    post_hash = compute_sha256(CANONICAL_DATASET)
    assert post_hash == EXPECTED_SHA256, (
        f"Regeneration is not deterministic! Expected {EXPECTED_SHA256}, got {post_hash}"
    )


# ---------------------------------------------------------------------------
# Test O: Reproducible train/test splitting
# ---------------------------------------------------------------------------
def test_req_o_reproducible_train_test_splitting():
    df = pd.read_csv(CANONICAL_DATASET)
    X = df[list(CANONICAL_FEATURE_NAMES)]
    y = df[CANONICAL_TARGET_NAME].values

    # Run split twice with seed 100
    X_tr1, X_te1, y_tr1, y_te1 = train_test_split(X, y, test_size=0.20, random_state=100, stratify=y)
    X_tr2, X_te2, y_tr2, y_te2 = train_test_split(X, y, test_size=0.20, random_state=100, stratify=y)

    assert np.array_equal(X_tr1.values, X_tr2.values)
    assert np.array_equal(X_te1.values, X_te2.values)
    assert np.array_equal(y_tr1, y_tr2)
    assert np.array_equal(y_te1, y_te2)


# ---------------------------------------------------------------------------
# Test P: Programmatic metric generation
# ---------------------------------------------------------------------------
def test_req_p_programmatic_metric_generation():
    metrics_path = PROJECT_ROOT / "experiments" / "results" / "ml4_statistical_reproduction.json"
    assert metrics_path.exists(), "Missing ml4_statistical_reproduction.json"

    with open(metrics_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    stats_summary = data.get("summary_statistics", {})
    for metric in ["accuracy", "precision", "recall", "f1", "roc_auc", "fpr", "fnr"]:
        assert metric in stats_summary, f"Metric {metric} missing from reproduction summary!"
        rf_mean = stats_summary[metric]["rf"]["mean"]
        ens_mean = stats_summary[metric]["ens"]["mean"]
        assert isinstance(rf_mean, float)
        assert isinstance(ens_mean, float)
        assert 0.0 <= rf_mean <= 1.0
        assert 0.0 <= ens_mean <= 1.0


# ---------------------------------------------------------------------------
# Test Q: Programmatic statistical generation
# ---------------------------------------------------------------------------
def test_req_q_programmatic_statistical_generation():
    metrics_path = PROJECT_ROOT / "experiments" / "results" / "ml4_statistical_reproduction.json"
    with open(metrics_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    st_tests = data.get("statistical_tests", {})
    assert "accuracy" in st_tests
    assert "f1" in st_tests
    acc_tests = st_tests["accuracy"]["ens_vs_rf"]
    assert "wilcoxon_stat" in acc_tests
    assert "wilcoxon_p_value" in acc_tests
    assert "paired_t_stat" in acc_tests
    assert "paired_t_p_value" in acc_tests
    assert "cohens_d" in acc_tests

    # Verify contingency analysis
    contingency = data.get("contingency_discordance_analysis", {})
    assert "mcnemar_exact_p_value" in contingency
    assert "fisher_exact_p_value" in contingency


# ---------------------------------------------------------------------------
# Test R: Run A / Run B reproducibility
# ---------------------------------------------------------------------------
def test_req_r_run_a_run_b_reproducibility():
    repro_path = PROJECT_ROOT / "experiments" / "results" / "ml4_reproducibility.json"
    assert repro_path.exists(), "Missing ml4_reproducibility.json"

    with open(repro_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("dataset_hash_match") is True
    assert data.get("discrete_metrics_bitwise_equal") is True
    assert data.get("predictions_bitwise_equal") is True
    assert data.get("probabilities_numerically_close") is True
    assert data.get("probabilities_max_abs_difference") < 1e-12
    assert "BITWISE_DETERMINISTIC" in data.get("determinism_classification")


# ---------------------------------------------------------------------------
# Test S: No stale active dataset references
# ---------------------------------------------------------------------------
def test_req_s_no_stale_active_dataset_references():
    active_scripts = [
        PROJECT_ROOT / "experiments" / "reproduce_all.py",
        PROJECT_ROOT / "experiments" / "reproduce_clean_paper.py",
        PROJECT_ROOT / "experiments" / "validate_remediated_clustering.py",
        PROJECT_ROOT / "experiments" / "run_latency_benchmark.py",
    ]

    for script_path in active_scripts:
        assert script_path.exists(), f"Missing active script: {script_path}"
        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Must not reference historical contaminated datasets
        assert "training_dataset.csv" not in content, (
            f"Stale dataset training_dataset.csv referenced in {script_path.name}"
        )
        assert "labeled_events_v2_enhanced.csv" not in content, (
            f"Stale dataset labeled_events_v2_enhanced.csv referenced in {script_path.name}"
        )
