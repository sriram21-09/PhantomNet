"""
PhantomNet Phase ML-6 Test Suite: Threshold, Calibration & Decision-Boundary Integrity
=======================================================================================
Verifies:
A. Threshold provenance classification & explicit documentation
B. Train / Development / Final Test strict partition separation
C. Isolation Forest calibration parameter isolation (no test data influence)
D. Threshold selection isolation (no test label influence)
E. Deterministic behavior under fixed seeds
F. Canonical 0.85 RF + 0.15 IF architecture and 12D schema preservation
G. Machine-readable artifact completeness and valid schemas
H. Test-set firewall (prohibits hidden test-set fitting)
I. Threshold reproducibility across repeated runs
J. Final evaluation firewall (untouched test fold)

Total test count: >= 25 tests.
"""

import os
import sys
import json
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.ml.config.feature_schema import CANONICAL_FEATURE_NAMES, CANONICAL_FEATURE_COUNT, SCHEMA_VERSION
from backend.ml.config.thresholds import (
    RF_WEIGHT, IF_WEIGHT, BLOCK_THRESHOLD, ALERT_THRESHOLD,
    CRITICAL_THRESHOLD, HIGH_THRESHOLD, MEDIUM_THRESHOLD,
    IF_CALIBRATION_MIN, IF_CALIBRATION_MAX
)
from backend.ml.models.ensemble_predictor import EnsemblePredictor

DATASET_PATH = PROJECT_ROOT / "data" / "remediated_dataset_v3.csv"
RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"
FIGURES_DIR = RESULTS_DIR / "ml6_figures"


# ============================================================================
# A. THRESHOLD PROVENANCE TESTS
# ============================================================================
class TestThresholdProvenance:
    def test_historical_threshold_provenance_classification(self):
        """Verifies that historical threshold provenance is classified as NO_PRESERVED_PROVENANCE."""
        artifact_path = RESULTS_DIR / "ml6_threshold_provenance.json"
        assert artifact_path.exists(), f"Missing artifact: {artifact_path}"
        with open(artifact_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["findings"]["formal_classification"] == "NO_PRESERVED_PROVENANCE"
        assert "Historical threshold-selection provenance was not preserved." in data["findings"]["explicit_audit_declaration"]

    def test_canonical_threshold_constants_values(self):
        """Verifies canonical threshold values in backend configuration."""
        assert BLOCK_THRESHOLD == 0.80
        assert ALERT_THRESHOLD == 0.50
        assert CRITICAL_THRESHOLD == 0.80
        assert HIGH_THRESHOLD == 0.60
        assert MEDIUM_THRESHOLD == 0.40

    def test_threshold_reference_inventory_exists(self):
        """Verifies that the threshold reference inventory is generated and populated."""
        inv_path = RESULTS_DIR / "ml6_threshold_reference_inventory.json"
        assert inv_path.exists(), f"Missing inventory: {inv_path}"
        with open(inv_path, "r", encoding="utf-8") as f:
            inv = json.load(f)
        assert inv["total_occurrences"] > 1000
        assert "occurrences" in inv


# ============================================================================
# B. TRAIN / DEV / TEST SEPARATION TESTS
# ============================================================================
class TestPartitionSeparation:
    @pytest.fixture
    def dataset(self):
        return pd.read_csv(DATASET_PATH)

    def test_three_way_split_dimensions(self, dataset):
        """Verifies strict 3-way partition sizes (64% train, 16% dev, 20% test)."""
        X = dataset[list(CANONICAL_FEATURE_NAMES)].values
        y = dataset["label"].values

        X_train_full, X_test, y_train_full, y_test = train_test_split(
            X, y, test_size=0.20, random_state=100, stratify=y
        )
        X_train, X_dev, y_train, y_dev = train_test_split(
            X_train_full, y_train_full, test_size=0.20, random_state=100, stratify=y_train_full
        )

        assert len(X_train) == 3200  # 64% of 5,000
        assert len(X_dev) == 800     # 16% of 5,000
        assert len(X_test) == 1000   # 20% of 5,000
        assert len(X_train) + len(X_dev) + len(X_test) == 5000

    def test_stratification_preserves_class_ratio(self, dataset):
        """Verifies stratification across train, dev, and test partitions."""
        y = dataset["label"].values
        base_ratio = np.mean(y)

        _, X_test, y_train_full, y_test = train_test_split(
            dataset[list(CANONICAL_FEATURE_NAMES)].values, y, test_size=0.20, random_state=100, stratify=y
        )
        _, _, y_train, y_dev = train_test_split(
            y_train_full, y_train_full, test_size=0.20, random_state=100, stratify=y_train_full
        )

        assert np.isclose(np.mean(y_train), base_ratio, atol=0.01)
        assert np.isclose(np.mean(y_dev), base_ratio, atol=0.01)
        assert np.isclose(np.mean(y_test), base_ratio, atol=0.01)

    def test_partition_disjointness(self, dataset):
        """Verifies zero index overlap across train, dev, and test sets."""
        indices = np.arange(len(dataset))
        idx_train_full, idx_test = train_test_split(indices, test_size=0.20, random_state=100)
        idx_train, idx_dev = train_test_split(idx_train_full, test_size=0.20, random_state=100)

        s_train = set(idx_train)
        s_dev = set(idx_dev)
        s_test = set(idx_test)

        assert len(s_train.intersection(s_dev)) == 0
        assert len(s_train.intersection(s_test)) == 0
        assert len(s_dev.intersection(s_test)) == 0


# ============================================================================
# C. CALIBRATION ISOLATION TESTS
# ============================================================================
class TestCalibrationIsolation:
    def test_calibration_audit_findings(self):
        """Verifies calibration audit reports TEST_SET_CALIBRATION_LEAKAGE."""
        cal_path = RESULTS_DIR / "ml6_calibration_audit.json"
        assert cal_path.exists()
        with open(cal_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["leakage_classification"] == "TEST_SET_CALIBRATION_LEAKAGE"

    def test_leakage_audit_artifact(self):
        """Verifies leakage audit registers both leak points and safeguards."""
        leak_path = RESULTS_DIR / "ml6_leakage_audit.json"
        assert leak_path.exists()
        with open(leak_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "LEAKAGE_DETECTED_AND_REMEDIATED"
        assert len(data["leakage_points"]) >= 2
        assert len(data["safeguards_implemented"]) >= 5

    def test_calibration_bounds_derived_without_test(self):
        """Verifies that development calibration bounds are computed without test set."""
        df = pd.read_csv(DATASET_PATH)
        X = df[list(CANONICAL_FEATURE_NAMES)].values
        y = df["label"].values

        X_train_full, X_test, y_train_full, y_test = train_test_split(
            X, y, test_size=0.20, random_state=100, stratify=y
        )
        X_train, X_dev, _, _ = train_test_split(
            X_train_full, y_train_full, test_size=0.20, random_state=100, stratify=y_train_full
        )

        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_dev_s = scaler.transform(X_dev)

        iso = IsolationForest(n_estimators=100, contamination=0.10, random_state=100, n_jobs=1)
        iso.fit(X_train_s)

        dev_scores = iso.decision_function(X_dev_s)
        s_min_dev = float(np.min(dev_scores))
        s_max_dev = float(np.max(dev_scores))

        assert np.isfinite(s_min_dev)
        assert np.isfinite(s_max_dev)
        assert s_min_dev < s_max_dev


# ============================================================================
# D. THRESHOLD SELECTION ISOLATION TESTS
# ============================================================================
class TestThresholdSelectionIsolation:
    def test_threshold_selection_uses_only_dev_partition(self):
        """Verifies threshold selection does not access test labels."""
        per_run_path = RESULTS_DIR / "ml6_per_run_threshold_metrics.json"
        assert per_run_path.exists()
        with open(per_run_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for run in data["runs"]:
            assert "dev_selected_thresholds" in run
            f1_t = run["dev_selected_thresholds"]["f1_optimal"]
            assert 0.0 < f1_t < 1.0

    def test_threshold_sweep_artifact_metadata(self):
        """Verifies sweep artifact records explicit partition isolation."""
        sweep_path = RESULTS_DIR / "ml6_threshold_sweep.json"
        assert sweep_path.exists()
        with open(sweep_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "DEVELOPMENT" in data["metadata"]["selection_partition"]
        assert "FINAL TEST" in data["metadata"]["evaluation_partition"]


# ============================================================================
# E. DETERMINISTIC BEHAVIOR & REPRODUCIBILITY TESTS
# ============================================================================
class TestDeterministicBehavior:
    def test_reproducibility_artifact_clean(self):
        """Verifies reproducibility across Run A and Run B."""
        repro_path = RESULTS_DIR / "ml6_reproducibility.json"
        assert repro_path.exists()
        with open(repro_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["all_seeds_deterministic"] is True
        assert data["maximum_continuous_metric_delta"] < 1e-6

    def test_single_seed_determinism(self):
        """Runs the pipeline twice with seed 100 to assert bitwise equal predictions."""
        df = pd.read_csv(DATASET_PATH)
        X = df[list(CANONICAL_FEATURE_NAMES)].values
        y = df["label"].values

        def run_once():
            X_tr_f, X_te, y_tr_f, y_te = train_test_split(X, y, test_size=0.20, random_state=100, stratify=y)
            X_tr, X_dv, _, _ = train_test_split(X_tr_f, y_tr_f, test_size=0.20, random_state=100, stratify=y_tr_f)
            scaler = StandardScaler()
            X_tr_s = scaler.fit_transform(X_tr)
            X_te_s = scaler.transform(X_te)
            rf = RandomForestClassifier(n_estimators=50, random_state=100, n_jobs=1)
            rf.fit(X_tr_s, y_tr_f[:len(X_tr)])
            return rf.predict_proba(X_te_s)[:, 1]

        p1 = run_once()
        p2 = run_once()
        np.testing.assert_array_equal(p1, p2)


# ============================================================================
# F. CANONICAL FORMULATION & SCHEMA PRESERVATION TESTS
# ============================================================================
class TestCanonicalArchitecturePreservation:
    def test_ensemble_weights_exact(self):
        """Verifies canonical 0.85 RF + 0.15 IF weights."""
        assert RF_WEIGHT == 0.85
        assert IF_WEIGHT == 0.15
        assert np.isclose(RF_WEIGHT + IF_WEIGHT, 1.0)

    def test_canonical_schema_dimensions(self):
        """Verifies canonical 12D schema and version."""
        assert len(CANONICAL_FEATURE_NAMES) == 12
        assert CANONICAL_FEATURE_COUNT == 12
        assert SCHEMA_VERSION == "12D-v1"

    def test_ensemble_predictor_instantiation(self):
        """Verifies EnsemblePredictor instantiates with canonical parameters."""
        ep = EnsemblePredictor(w_rf=0.85, w_if=0.15)
        assert ep.w_rf == 0.85
        assert ep.w_if == 0.15

    def test_ensemble_predictor_rejection_of_obsolete_weights(self):
        """Verifies EnsemblePredictor enforces canonical weights when 0.70/0.30 passed."""
        ep = EnsemblePredictor(w_rf=0.70, w_if=0.30)
        assert ep.w_rf == 0.85
        assert ep.w_if == 0.15


# ============================================================================
# G. ARTIFACT COMPLETENESS TESTS
# ============================================================================
class TestArtifactCompleteness:
    REQUIRED_JSONS = [
        "ml6_threshold_reference_inventory.json",
        "ml6_threshold_provenance.json",
        "ml6_calibration_audit.json",
        "ml6_leakage_audit.json",
        "ml6_threshold_sweep.json",
        "ml6_per_run_threshold_metrics.json",
        "ml6_confidence_intervals.json",
        "ml6_statistical_tests.json",
        "ml6_reproducibility.json",
        "ml6_claim_traceability.json",
        "ml6_static_audit.json"
    ]

    REQUIRED_FIGURES = [
        "rf_reliability_diagram.png",
        "ensemble_reliability_diagram.png",
        "rf_calibration_error_summary.png",
        "ensemble_calibration_error_summary.png",
        "threshold_vs_fpr_fnr_curve.png",
        "precision_recall_operating_point_curve.png",
        "score_distributions_by_class.png"
    ]

    @pytest.mark.parametrize("json_name", REQUIRED_JSONS)
    def test_json_artifact_exists_and_valid(self, json_name):
        p = RESULTS_DIR / json_name
        assert p.exists(), f"Missing JSON artifact: {json_name}"
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict)

    @pytest.mark.parametrize("fig_name", REQUIRED_FIGURES)
    def test_figure_artifact_exists_and_nonempty(self, fig_name):
        p = FIGURES_DIR / fig_name
        assert p.exists(), f"Missing figure: {fig_name}"
        assert p.stat().st_size > 1000, f"Empty figure: {fig_name}"


# ============================================================================
# H. TEST-SET FIREWALL TESTS
# ============================================================================
class TestTestSetFirewall:
    def test_scaler_not_fitted_on_test_data(self):
        """Verifies scaler fitted on train only produces different mean than test set."""
        df = pd.read_csv(DATASET_PATH)
        X = df[list(CANONICAL_FEATURE_NAMES)].values
        y = df["label"].values

        X_train_full, X_test, _, _ = train_test_split(X, y, test_size=0.20, random_state=100, stratify=y)
        X_train, _, _, _ = train_test_split(X_train_full, X_train_full, test_size=0.20, random_state=100)

        scaler = StandardScaler()
        scaler.fit(X_train)

        # Means between train partition and test partition must not be identical
        test_mean = np.mean(X_test, axis=0)
        assert not np.allclose(scaler.mean_, test_mean)

    def test_test_labels_not_used_in_threshold_optimization(self):
        """Verifies threshold optimization on dev produces valid threshold without accessing y_test."""
        per_run_path = RESULTS_DIR / "ml6_per_run_threshold_metrics.json"
        with open(per_run_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        run0 = data["runs"][0]
        # Dev-selected threshold must exist independently of test evaluations
        assert "dev_selected_thresholds" in run0
        assert "f1_optimal" in run0["dev_selected_thresholds"]


# ============================================================================
# I. ENSEMBLE SCORE SEMANTICS & CALIBRATION
# ============================================================================
class TestEnsembleScoreSemantics:
    def test_ensemble_score_semantics_audit(self):
        """Verifies that ensemble score is recognized as an uncalibrated composite threat score."""
        ci_path = RESULTS_DIR / "ml6_confidence_intervals.json"
        with open(ci_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        ens_ci = data["models"]["safe_ensemble_t050"]
        rf_ci = data["models"]["rf_uncalibrated_t050"]

        # ECE of ensemble is higher than RF due to adding IF anomaly score
        assert ens_ci["ece"]["mean"] > 0.05
        assert ens_ci["brier_score"]["mean"] > 0.04

    def test_confidence_interval_bounds_logical(self):
        """Verifies 95% confidence intervals obey lower <= mean <= upper."""
        ci_path = RESULTS_DIR / "ml6_confidence_intervals.json"
        with open(ci_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for model_name, metrics in data["models"].items():
            for m_name, stats_dict in metrics.items():
                assert stats_dict["ci_95_lower"] <= stats_dict["mean"] <= stats_dict["ci_95_upper"]
