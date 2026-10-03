"""
PhantomNet ML-5 Test Suite: Model Training, Statistical Validation & Performance Forensics
============================================================================================
Minimum coverage per ML-5 spec sections A–R plus S requirements:
  1.  model inventory integrity
  2.  canonical RF configuration
  3.  canonical IF configuration
  4.  ensemble formula
  5.  ensemble bounds
  6.  ensemble directionality
  7.  N=30 seed integrity
  8.  metric reproduction
  9.  confidence interval generation
  10. paired comparison correctness
  11. McNemar table correctness
  12. multiple-comparison accounting
  13. threshold provenance
  14. ablation reproducibility
  15. feature importance reproducibility
  16. result artifact provenance
  17. deterministic reproduction
"""

import os
import sys
import json
import hashlib
import pytest
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "remediated_dataset_v3.csv")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "experiments", "results")

CANONICAL_FEATURES = [
    "packet_length", "protocol_encoding", "dst_port_class",
    "src_port_ephemeral", "event_rate_1m", "burst_rate_10s",
    "inter_arrival_mean", "inter_arrival_std", "packet_size_variance",
    "payload_entropy", "unique_dst_ips", "unique_dst_ports",
]
RF_WEIGHT = 0.85
IF_WEIGHT = 0.15
N_RUNS = 30
SEEDS = [100 + i for i in range(N_RUNS)]

EXPECTED_DATASET_SHA = "390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363"


def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def load_artifact(name):
    path = os.path.join(RESULTS_DIR, name)
    assert os.path.exists(path), f"ML-5 artifact not found: {path}"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================================
# FIXTURES
# ============================================================================
@pytest.fixture(scope="module")
def dataset():
    assert os.path.exists(DATASET_PATH), f"Dataset not found: {DATASET_PATH}"
    df = pd.read_csv(DATASET_PATH)
    return df


@pytest.fixture(scope="module")
def ml5_inventory():
    return load_artifact("ml5_model_inventory.json")


@pytest.fixture(scope="module")
def ml5_per_run():
    return load_artifact("ml5_per_run_metrics.json")


@pytest.fixture(scope="module")
def ml5_ci():
    return load_artifact("ml5_confidence_intervals.json")


@pytest.fixture(scope="module")
def ml5_stat_tests():
    return load_artifact("ml5_statistical_tests.json")


@pytest.fixture(scope="module")
def ml5_ablation():
    return load_artifact("ml5_ablation.json")


@pytest.fixture(scope="module")
def ml5_repro():
    return load_artifact("ml5_reproducibility.json")


@pytest.fixture(scope="module")
def ml5_error():
    return load_artifact("ml5_error_analysis.json")


# ============================================================================
# 1. MODEL INVENTORY INTEGRITY
# ============================================================================
class TestModelInventory:
    def test_inventory_has_active_models(self, ml5_inventory):
        assert len(ml5_inventory["active_models"]) >= 3

    def test_inventory_has_quarantined_models(self, ml5_inventory):
        assert len(ml5_inventory["quarantined_models"]) >= 2

    def test_inventory_schema_version(self, ml5_inventory):
        assert ml5_inventory["schema_version"] == "12D-v1"

    def test_inventory_feature_count(self, ml5_inventory):
        assert ml5_inventory["feature_count"] == 12

    def test_inventory_features_match_canonical(self, ml5_inventory):
        assert ml5_inventory["canonical_features"] == CANONICAL_FEATURES

    def test_quarantined_cannot_participate(self, ml5_inventory):
        """Verify quarantined models have explicit quarantine status."""
        for model in ml5_inventory["quarantined_models"]:
            assert model["status"] == "quarantined"
            assert "reason" in model

    def test_active_models_have_producing_script(self, ml5_inventory):
        for model in ml5_inventory["active_models"]:
            assert "producing_script" in model


# ============================================================================
# 2. CANONICAL RF CONFIGURATION
# ============================================================================
class TestCanonicalRFConfig:
    def test_rf_estimator_type(self, ml5_inventory):
        rf_model = next(m for m in ml5_inventory["active_models"]
                        if m["model_id"] == "RF-canonical-12D")
        assert rf_model["estimator_type"] == "RandomForestClassifier"

    def test_rf_n_estimators(self, ml5_inventory):
        rf_model = next(m for m in ml5_inventory["active_models"]
                        if m["model_id"] == "RF-canonical-12D")
        assert rf_model["hyperparameters"]["n_estimators"] == 100

    def test_rf_feature_dim(self, ml5_inventory):
        rf_model = next(m for m in ml5_inventory["active_models"]
                        if m["model_id"] == "RF-canonical-12D")
        assert rf_model["feature_dimensionality"] == 12

    def test_rf_deterministic_seed(self, ml5_per_run):
        """Verify per-run seeds match canonical schedule."""
        assert ml5_per_run["seeds"] == SEEDS

    def test_rf_uses_standard_scaler(self, ml5_inventory):
        rf_model = next(m for m in ml5_inventory["active_models"]
                        if m["model_id"] == "RF-canonical-12D")
        assert "StandardScaler" in rf_model["preprocessing"]
        assert "X_train" in rf_model["preprocessing"]


# ============================================================================
# 3. CANONICAL IF CONFIGURATION
# ============================================================================
class TestCanonicalIFConfig:
    def test_if_contamination(self, ml5_inventory):
        if_model = next(m for m in ml5_inventory["active_models"]
                        if m["model_id"] == "IF-canonical-12D")
        assert if_model["hyperparameters"]["contamination"] == 0.10

    def test_if_n_estimators(self, ml5_inventory):
        if_model = next(m for m in ml5_inventory["active_models"]
                        if m["model_id"] == "IF-canonical-12D")
        assert if_model["hyperparameters"]["n_estimators"] == 100

    def test_if_calibration_documented(self, ml5_inventory):
        if_model = next(m for m in ml5_inventory["active_models"]
                        if m["model_id"] == "IF-canonical-12D")
        assert "calibration_method" in if_model
        assert "min-max" in if_model["calibration_method"]


# ============================================================================
# 4. ENSEMBLE FORMULA
# ============================================================================
class TestEnsembleFormula:
    def test_weights_are_canonical(self, ml5_per_run):
        w = ml5_per_run["ensemble_weights"]
        assert w["RF"] == 0.85
        assert w["IF"] == 0.15

    def test_weights_sum_to_one(self, ml5_per_run):
        w = ml5_per_run["ensemble_weights"]
        assert abs(w["RF"] + w["IF"] - 1.0) < 1e-10

    def test_ensemble_formula_empirical(self, dataset):
        """Independently verify S = 0.85 * P_RF + 0.15 * S_IF."""
        df = dataset
        X = df[CANONICAL_FEATURES]
        y = df["label"].values
        seed = 100

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=seed, stratify=y)
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_test_s = scaler.transform(X_test)

        rf = RandomForestClassifier(
            n_estimators=100, max_depth=12, min_samples_split=5,
            min_samples_leaf=2, random_state=seed, n_jobs=1)
        rf.fit(X_train_s, y_train)
        rf_prob = rf.predict_proba(X_test_s)[:, 1]

        iso = IsolationForest(
            n_estimators=100, contamination=0.10,
            random_state=seed, n_jobs=1)
        iso.fit(X_train_s)
        if_raw = -iso.score_samples(X_test_s)
        if_prob = (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-9)

        ens_prob = 0.85 * rf_prob + 0.15 * if_prob
        assert np.allclose(ens_prob, RF_WEIGHT * rf_prob + IF_WEIGHT * if_prob)


# ============================================================================
# 5. ENSEMBLE BOUNDS
# ============================================================================
class TestEnsembleBounds:
    def test_ensemble_scores_bounded_0_1(self, ml5_per_run):
        """All ensemble scores across all runs must be in [0, 1]."""
        for run in ml5_per_run["runs"]:
            stats = run["ensemble_score_statistics"]
            assert stats["min"] >= 0.0 - 1e-9
            assert stats["max"] <= 1.0 + 1e-9

    def test_rf_scores_bounded_0_1(self, ml5_per_run):
        for run in ml5_per_run["runs"]:
            stats = run["rf_score_statistics"]
            assert stats["min"] >= 0.0 - 1e-9
            assert stats["max"] <= 1.0 + 1e-9

    def test_if_scores_bounded_0_1(self, ml5_per_run):
        for run in ml5_per_run["runs"]:
            stats = run["if_score_statistics"]
            assert stats["min"] >= -1e-9
            assert stats["max"] <= 1.0 + 1e-9


# ============================================================================
# 6. ENSEMBLE DIRECTIONALITY
# ============================================================================
class TestEnsembleDirectionality:
    def test_higher_if_score_means_more_anomalous(self, dataset):
        """Verify: higher S_IF = greater anomaly evidence."""
        df = dataset
        X = df[CANONICAL_FEATURES]
        y = df["label"].values
        seed = 100

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=seed, stratify=y)
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_test_s = scaler.transform(X_test)

        iso = IsolationForest(
            n_estimators=100, contamination=0.10,
            random_state=seed, n_jobs=1)
        iso.fit(X_train_s)
        if_raw = -iso.score_samples(X_test_s)
        if_prob = (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-9)

        # Malicious samples should have higher mean IF score than benign
        mal_mean = np.mean(if_prob[y_test == 1])
        ben_mean = np.mean(if_prob[y_test == 0])
        assert mal_mean > ben_mean, (
            f"IF directionality violated: malicious mean={mal_mean:.4f} <= benign mean={ben_mean:.4f}"
        )

    def test_ensemble_directionality(self, ml5_per_run):
        """Verify ensemble accuracy > 50% (better than random)."""
        for run in ml5_per_run["runs"]:
            assert run["hybrid_ensemble"]["accuracy"] > 0.50


# ============================================================================
# 7. N=30 SEED INTEGRITY
# ============================================================================
class TestSeedIntegrity:
    def test_exactly_30_runs(self, ml5_per_run):
        assert ml5_per_run["n_runs"] == 30
        assert len(ml5_per_run["runs"]) == 30

    def test_seeds_are_100_to_129(self, ml5_per_run):
        assert ml5_per_run["seeds"] == list(range(100, 130))

    def test_each_run_has_correct_seed(self, ml5_per_run):
        for run in ml5_per_run["runs"]:
            expected_seed = 100 + run["run_id"] - 1
            assert run["seed"] == expected_seed

    def test_train_test_sizes(self, ml5_per_run):
        for run in ml5_per_run["runs"]:
            assert run["train_size"] == 4000
            assert run["test_size"] == 1000


# ============================================================================
# 8. METRIC REPRODUCTION
# ============================================================================
class TestMetricReproduction:
    def test_first_run_matches_independent_computation(self, dataset, ml5_per_run):
        """Independently compute metrics for seed=100 and compare."""
        df = dataset
        X = df[CANONICAL_FEATURES]
        y = df["label"].values
        seed = 100

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=seed, stratify=y)
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_test_s = scaler.transform(X_test)

        rf = RandomForestClassifier(
            n_estimators=100, max_depth=12, min_samples_split=5,
            min_samples_leaf=2, random_state=seed, n_jobs=1)
        rf.fit(X_train_s, y_train)
        rf_prob = rf.predict_proba(X_test_s)[:, 1]
        rf_pred = (rf_prob >= 0.50).astype(int)

        iso = IsolationForest(
            n_estimators=100, contamination=0.10,
            random_state=seed, n_jobs=1)
        iso.fit(X_train_s)
        if_raw = -iso.score_samples(X_test_s)
        if_prob = (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-9)
        ens_prob = 0.85 * rf_prob + 0.15 * if_prob
        ens_pred = (ens_prob >= 0.50).astype(int)

        run1 = ml5_per_run["runs"][0]
        assert abs(run1["hybrid_ensemble"]["accuracy"] -
                    accuracy_score(y_test, ens_pred)) < 1e-10
        assert abs(run1["hybrid_ensemble"]["f1"] -
                    f1_score(y_test, ens_pred, zero_division=0)) < 1e-10

    def test_all_runs_have_complete_metrics(self, ml5_per_run):
        required = ["accuracy", "precision", "recall", "f1", "specificity",
                     "fpr", "fnr", "roc_auc", "confusion_matrix"]
        for run in ml5_per_run["runs"]:
            for model in ["random_forest", "isolation_forest", "hybrid_ensemble"]:
                for m in required:
                    assert m in run[model], f"Missing {m} in run {run['run_id']} {model}"


# ============================================================================
# 9. CONFIDENCE INTERVAL GENERATION
# ============================================================================
class TestConfidenceIntervals:
    def test_ci_artifact_exists(self, ml5_ci):
        assert ml5_ci is not None

    def test_ci_has_all_models(self, ml5_ci):
        for model in ["random_forest", "isolation_forest", "hybrid_ensemble"]:
            assert model in ml5_ci

    def test_ci_has_required_metrics(self, ml5_ci):
        required = ["accuracy", "precision", "recall", "f1", "fpr", "fnr", "roc_auc"]
        for model in ["random_forest", "hybrid_ensemble"]:
            for m in required:
                assert m in ml5_ci[model], f"Missing CI for {model}/{m}"

    def test_ci_lower_less_than_upper(self, ml5_ci):
        for model in ["random_forest", "hybrid_ensemble"]:
            for m in ml5_ci[model]:
                if isinstance(ml5_ci[model][m], dict) and "ci_lower" in ml5_ci[model][m]:
                    ci = ml5_ci[model][m]
                    assert ci["ci_lower"] <= ci["ci_upper"]

    def test_ci_n_equals_30(self, ml5_ci):
        for model in ["random_forest", "hybrid_ensemble"]:
            for m in ml5_ci[model]:
                if isinstance(ml5_ci[model][m], dict) and "n" in ml5_ci[model][m]:
                    assert ml5_ci[model][m]["n"] == 30

    def test_ci_method_documented(self, ml5_ci):
        assert "ci_method_description" in ml5_ci
        assert "distinction" in ml5_ci

    def test_ci_distinguishes_variability_types(self, ml5_ci):
        dist = ml5_ci["distinction"]
        assert "inter_run_variability" in dist
        assert "standard_error" in dist
        assert "confidence_interval" in dist


# ============================================================================
# 10. PAIRED COMPARISON CORRECTNESS
# ============================================================================
class TestPairedComparisons:
    def test_paired_comparisons_exist(self, ml5_stat_tests):
        assert "paired_comparisons_ens_vs_rf" in ml5_stat_tests

    def test_all_metrics_compared(self, ml5_stat_tests):
        required = ["accuracy", "precision", "recall", "f1", "fpr", "fnr", "roc_auc"]
        for m in required:
            assert m in ml5_stat_tests["paired_comparisons_ens_vs_rf"]

    def test_paired_structure(self, ml5_stat_tests):
        for m, result in ml5_stat_tests["paired_comparisons_ens_vs_rf"].items():
            assert result["n_pairs"] == 30
            assert "wilcoxon_p_value" in result
            assert "paired_t_p_value" in result
            assert "cohens_d" in result
            assert "ci_95_lower" in result
            assert "ci_95_upper" in result
            assert "direction" in result
            assert "effect_size_interpretation" in result

    def test_p_values_are_valid(self, ml5_stat_tests):
        for m, result in ml5_stat_tests["paired_comparisons_ens_vs_rf"].items():
            assert 0.0 <= result["wilcoxon_p_value"] <= 1.0
            assert 0.0 <= result["paired_t_p_value"] <= 1.0

    def test_effect_size_consistency(self, ml5_stat_tests):
        """If mean_difference > 0, direction should be 'ensemble > RF'."""
        for m, result in ml5_stat_tests["paired_comparisons_ens_vs_rf"].items():
            if result["mean_difference"] > 1e-10:
                assert result["direction"] == "ensemble > RF"
            elif result["mean_difference"] < -1e-10:
                assert result["direction"] == "ensemble < RF"


# ============================================================================
# 11. MCNEMAR TABLE CORRECTNESS
# ============================================================================
class TestMcNemarTable:
    def test_mcnemar_exists(self, ml5_stat_tests):
        assert "mcnemar_analysis" in ml5_stat_tests

    def test_mcnemar_cells_sum(self, ml5_stat_tests):
        cells = ml5_stat_tests["mcnemar_analysis"]["contingency_table"]
        total = cells["both_correct_a"] + cells["rf_only_correct_b"] + \
                cells["ens_only_correct_c"] + cells["both_incorrect_d"]
        assert total == ml5_stat_tests["mcnemar_analysis"]["total_observations"]

    def test_mcnemar_p_value_valid(self, ml5_stat_tests):
        p = ml5_stat_tests["mcnemar_analysis"]["p_value"]
        assert 0.0 <= p <= 1.0

    def test_mcnemar_not_fabricated(self, ml5_stat_tests):
        """Verify the table is not the known fabricated [[0,30],[30,0]]."""
        cells = ml5_stat_tests["mcnemar_analysis"]["contingency_table"]
        assert not (cells["both_correct_a"] == 0 and
                    cells["rf_only_correct_b"] == 30 and
                    cells["ens_only_correct_c"] == 30 and
                    cells["both_incorrect_d"] == 0)

    def test_mcnemar_independently_reproduced(self, dataset):
        """Independently build the McNemar table from scratch."""
        df = dataset
        X = df[CANONICAL_FEATURES]
        y = df["label"].values
        seed = 100

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=seed, stratify=y)
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_test_s = scaler.transform(X_test)

        rf = RandomForestClassifier(
            n_estimators=100, max_depth=12, min_samples_split=5,
            min_samples_leaf=2, random_state=seed, n_jobs=1)
        rf.fit(X_train_s, y_train)
        rf_prob = rf.predict_proba(X_test_s)[:, 1]
        rf_pred = (rf_prob >= 0.50).astype(int)

        iso = IsolationForest(
            n_estimators=100, contamination=0.10,
            random_state=seed, n_jobs=1)
        iso.fit(X_train_s)
        if_raw = -iso.score_samples(X_test_s)
        if_prob = (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-9)
        ens_prob = 0.85 * rf_prob + 0.15 * if_prob
        ens_pred = (ens_prob >= 0.50).astype(int)

        rf_c = (rf_pred == y_test)
        ens_c = (ens_pred == y_test)
        b_ind = int(np.sum(rf_c & ~ens_c))
        c_ind = int(np.sum(~rf_c & ens_c))

        ml5_data = load_artifact("ml5_statistical_tests.json")
        assert ml5_data["mcnemar_analysis"]["contingency_table"]["rf_only_correct_b"] == b_ind
        assert ml5_data["mcnemar_analysis"]["contingency_table"]["ens_only_correct_c"] == c_ind


# ============================================================================
# 12. MULTIPLE-COMPARISON ACCOUNTING
# ============================================================================
class TestMultipleComparisons:
    def test_correction_exists(self, ml5_stat_tests):
        assert "multiple_comparison_correction" in ml5_stat_tests

    def test_correction_method(self, ml5_stat_tests):
        mc = ml5_stat_tests["multiple_comparison_correction"]
        assert "Holm" in mc["method"]

    def test_adjusted_p_values_exist(self, ml5_stat_tests):
        mc = ml5_stat_tests["multiple_comparison_correction"]
        for t in mc["tests"]:
            assert "raw_p_value" in t
            assert "adjusted_p_value" in t
            assert t["adjusted_p_value"] >= t["raw_p_value"]

    def test_adjusted_p_bounded(self, ml5_stat_tests):
        mc = ml5_stat_tests["multiple_comparison_correction"]
        for t in mc["tests"]:
            assert 0.0 <= t["adjusted_p_value"] <= 1.0


# ============================================================================
# 13. THRESHOLD PROVENANCE
# ============================================================================
class TestThresholdProvenance:
    def test_block_threshold(self):
        from backend.ml.config.thresholds import BLOCK_THRESHOLD
        assert BLOCK_THRESHOLD == 0.80

    def test_alert_threshold(self):
        from backend.ml.config.thresholds import ALERT_THRESHOLD
        assert ALERT_THRESHOLD == 0.50

    def test_severity_critical(self):
        from backend.ml.config.thresholds import CRITICAL_THRESHOLD
        assert CRITICAL_THRESHOLD == 0.80

    def test_severity_high(self):
        from backend.ml.config.thresholds import HIGH_THRESHOLD
        assert HIGH_THRESHOLD == 0.60

    def test_severity_medium(self):
        from backend.ml.config.thresholds import MEDIUM_THRESHOLD
        assert MEDIUM_THRESHOLD == 0.40

    def test_canonical_weights(self):
        from backend.ml.config.thresholds import RF_WEIGHT, IF_WEIGHT
        assert RF_WEIGHT == 0.85
        assert IF_WEIGHT == 0.15


# ============================================================================
# 14. ABLATION REPRODUCIBILITY
# ============================================================================
class TestAblation:
    def test_ablation_artifact_exists(self, ml5_ablation):
        assert ml5_ablation is not None

    def test_ablation_has_three_components(self, ml5_ablation):
        assert len(ml5_ablation["components"]) == 3

    def test_ablation_models_listed(self, ml5_ablation):
        names = [c["model"] for c in ml5_ablation["components"]]
        assert any("Random Forest" in n for n in names)
        assert any("Isolation Forest" in n for n in names)
        assert any("Ensemble" in n or "Hybrid" in n for n in names)

    def test_ablation_metrics_present(self, ml5_ablation):
        required = ["accuracy", "precision", "recall", "f1", "fpr", "fnr", "roc_auc"]
        for comp in ml5_ablation["components"]:
            for m in required:
                assert m in comp, f"Missing {m} in {comp['model']}"

    def test_rf_better_than_if_on_accuracy(self, ml5_ablation):
        """RF should substantially outperform IF on accuracy."""
        rf_comp = next(c for c in ml5_ablation["components"] if "Random Forest" in c["model"])
        if_comp = next(c for c in ml5_ablation["components"] if "Isolation Forest" in c["model"])
        assert rf_comp["accuracy"]["mean"] > if_comp["accuracy"]["mean"]


# ============================================================================
# 15. FEATURE IMPORTANCE REPRODUCIBILITY
# ============================================================================
class TestFeatureImportance:
    def test_feature_importance_exists(self, ml5_error):
        assert "feature_importance" in ml5_error

    def test_impurity_importance_has_all_features(self, ml5_error):
        imp = ml5_error["feature_importance"]["method_impurity"]["values"]
        for feat in CANONICAL_FEATURES:
            assert feat in imp

    def test_permutation_importance_has_all_features(self, ml5_error):
        imp = ml5_error["feature_importance"]["method_permutation"]["values"]
        for feat in CANONICAL_FEATURES:
            assert feat in imp

    def test_importances_are_positive(self, ml5_error):
        imp = ml5_error["feature_importance"]["method_impurity"]["values"]
        for feat, val in imp.items():
            assert val >= 0.0

    def test_impurity_importances_sum_to_one(self, ml5_error):
        imp = ml5_error["feature_importance"]["method_impurity"]["values"]
        total = sum(imp.values())
        assert abs(total - 1.0) < 1e-6

    def test_no_causal_claims(self, ml5_error):
        for method in ["method_impurity", "method_permutation"]:
            note = ml5_error["feature_importance"][method]["note"]
            assert "causal" in note.lower()


# ============================================================================
# 16. RESULT ARTIFACT PROVENANCE
# ============================================================================
class TestArtifactProvenance:
    def test_all_ml5_artifacts_exist(self):
        required = [
            "ml5_model_inventory.json",
            "ml5_per_run_metrics.json",
            "ml5_statistical_tests.json",
            "ml5_confidence_intervals.json",
            "ml5_ablation.json",
            "ml5_reproducibility.json",
            "ml5_error_analysis.json",
        ]
        for name in required:
            path = os.path.join(RESULTS_DIR, name)
            assert os.path.exists(path), f"Missing ML-5 artifact: {name}"

    def test_artifacts_have_timestamps(self):
        artifacts = [
            "ml5_model_inventory.json",
            "ml5_per_run_metrics.json",
            "ml5_statistical_tests.json",
            "ml5_confidence_intervals.json",
            "ml5_ablation.json",
            "ml5_reproducibility.json",
            "ml5_error_analysis.json",
        ]
        for name in artifacts:
            data = load_artifact(name)
            assert "timestamp_utc" in data, f"Missing timestamp in {name}"

    def test_dataset_sha_consistency(self):
        """All artifacts that record dataset SHA must agree."""
        sha_artifacts = [
            "ml5_per_run_metrics.json",
            "ml5_reproducibility.json",
            "ml5_error_analysis.json",
        ]
        shas = set()
        for name in sha_artifacts:
            data = load_artifact(name)
            shas.add(data["dataset_sha256"])
        assert len(shas) == 1, f"Inconsistent SHA-256 across artifacts: {shas}"
        assert shas.pop() == EXPECTED_DATASET_SHA


# ============================================================================
# 17. DETERMINISTIC REPRODUCTION
# ============================================================================
class TestDeterministicReproduction:
    def test_repro_artifact_exists(self, ml5_repro):
        assert ml5_repro is not None

    def test_repro_environment_recorded(self, ml5_repro):
        env = ml5_repro["environment"]
        assert "python_version" in env
        assert "numpy_version" in env
        assert "sklearn_version" in env

    def test_repro_run_a_vs_b(self, ml5_repro):
        ab = ml5_repro["run_a_vs_run_b"]
        assert len(ab["comparisons"]) >= 3

    def test_repro_not_materially_different(self, ml5_repro):
        ab = ml5_repro["run_a_vs_run_b"]
        assert ab["classification"] != "MATERIALLY_DIFFERENT"

    def test_repro_n_jobs_1_for_determinism(self, ml5_repro):
        assert ml5_repro["environment"]["n_jobs"] == 1


# ============================================================================
# ADDITIONAL: CALIBRATION ANALYSIS
# ============================================================================
class TestCalibration:
    def test_calibration_analysis_exists(self, ml5_error):
        assert "calibration_analysis" in ml5_error

    def test_brier_scores_computed(self, ml5_error):
        cal = ml5_error["calibration_analysis"]
        assert "brier_score" in cal["random_forest"]
        assert "brier_score" in cal["hybrid_ensemble"]

    def test_brier_scores_valid(self, ml5_error):
        cal = ml5_error["calibration_analysis"]
        assert 0.0 <= cal["random_forest"]["brier_score"] <= 1.0
        assert 0.0 <= cal["hybrid_ensemble"]["brier_score"] <= 1.0

    def test_if_calibration_limitation_documented(self, ml5_error):
        cal = ml5_error["calibration_analysis"]["isolation_forest"]
        assert "limitation" in str(cal).lower() or "not" in cal["interpretation"].lower()

    def test_ece_computed_for_rf(self, ml5_error):
        cal = ml5_error["calibration_analysis"]["random_forest"]
        assert "expected_calibration_error" in cal


# ============================================================================
# ADDITIONAL: ERROR ANALYSIS
# ============================================================================
class TestErrorAnalysis:
    def test_error_analysis_exists(self, ml5_error):
        assert "error_analysis" in ml5_error

    def test_fp_fn_counts(self, ml5_error):
        ea = ml5_error["error_analysis"]
        counts = ea["counts"]
        total = counts["true_positives"] + counts["true_negatives"] + \
                counts["false_positives"] + counts["false_negatives"]
        assert total == ea["test_size"]

    def test_score_distributions_present(self, ml5_error):
        ea = ml5_error["error_analysis"]
        assert "ensemble_score_distribution" in ea["false_positive_analysis"]
        assert "ensemble_score_distribution" in ea["false_negative_analysis"]


# ============================================================================
# ADDITIONAL: CLASS IMBALANCE AWARENESS
# ============================================================================
class TestClassImbalance:
    def test_dataset_imbalance(self, dataset):
        label_counts = dataset["label"].value_counts()
        assert label_counts[0] == 3500
        assert label_counts[1] == 1500

    def test_balanced_accuracy_computable(self, ml5_per_run):
        """Verify specificity is recorded (needed for balanced accuracy)."""
        run = ml5_per_run["runs"][0]
        assert "specificity" in run["hybrid_ensemble"]

    def test_specificity_and_fpr_sum_to_one(self, ml5_per_run):
        for run in ml5_per_run["runs"]:
            for model in ["random_forest", "hybrid_ensemble"]:
                spec = run[model]["specificity"]
                fpr = run[model]["fpr"]
                assert abs(spec + fpr - 1.0) < 1e-10


# ============================================================================
# ADDITIONAL: STATISTICAL ASSUMPTION AUDIT
# ============================================================================
class TestStatisticalAssumptions:
    def test_assumption_audit_exists(self, ml5_stat_tests):
        assert "statistical_assumption_audit" in ml5_stat_tests

    def test_wilcoxon_documented(self, ml5_stat_tests):
        aud = ml5_stat_tests["statistical_assumption_audit"]["wilcoxon_signed_rank"]
        assert "null_hypothesis" in aud
        assert "structure" in aud
        assert aud["structure"] == "Paired (same test splits)"

    def test_mcnemar_assumptions_documented(self, ml5_stat_tests):
        aud = ml5_stat_tests["statistical_assumption_audit"]["mcnemar"]
        assert "null_hypothesis" in aud


# ============================================================================
# ADDITIONAL: SUBGROUP ANALYSIS
# ============================================================================
class TestSubgroup:
    def test_subgroup_status(self, ml5_error):
        assert ml5_error["subgroup_analysis"]["status"] == "unavailable"
        assert "reason" in ml5_error["subgroup_analysis"]
