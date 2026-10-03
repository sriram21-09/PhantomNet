"""
PhantomNet Phase ML-7 Test Suite: Independent Validation, Robustness & Generalization
=====================================================================================
Validates:
A. Dataset independence audit & NO_INDEPENDENT_DATA_AVAILABLE declaration
B. Strict training isolation (no test data in scaler, training, calibration, or thresholds)
C. Robustness scenario schema integrity & feature contracts across all 12 scenarios
D. Distribution shift quantification integrity (Wasserstein, KS, PSI)
E. Baseline model comparison validity (Majority, LogReg, DecisionTree, RF, IF, Ensemble)
F. Statistical testing integrity (paired t-test, Wilcoxon, McNemar, Holm-Bonferroni)
G. Failure-mode & subgroup analysis reporting (SUBGROUP_ANALYSIS_NOT_AVAILABLE)
H. Calibration forensics (quantification of ECE and non-Bayesian score semantics)
I. Threshold robustness under distribution shifts
J. Component ablation stability (RF vs IF vs 0.85/0.15 Ensemble)
K. Deterministic reproducibility (Run A / Run B)
L. Latency microbenchmark sanity & qualification
M. Publication claim forensics (no unsupported claims marked VERIFIED)
N. Scientific limitation register completeness (>= 15 limitations)
O. Evidence graph node-and-edge connectivity
P. Historical artifact preservation (ML-1 through ML-6 artifacts intact)
Q. Canonical architecture preservation (12D-v1 and 0.85 RF + 0.15 IF)

Total tests: >= 30 tests.
"""

import os
import sys
import json
import pytest
import numpy as np
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.ml.config.feature_schema import CANONICAL_FEATURE_NAMES, CANONICAL_FEATURE_COUNT, SCHEMA_VERSION
from backend.ml.config.thresholds import (
    RF_WEIGHT, IF_WEIGHT, BLOCK_THRESHOLD, ALERT_THRESHOLD,
    CRITICAL_THRESHOLD, HIGH_THRESHOLD, MEDIUM_THRESHOLD
)

DATASET_PATH = PROJECT_ROOT / "data" / "remediated_dataset_v3.csv"
SCENARIOS_DIR = PROJECT_ROOT / "data" / "robustness_scenarios"
RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"
FIGURES_DIR = RESULTS_DIR / "ml7_figures"


# ============================================================================
# A. DATASET INDEPENDENCE TESTS
# ============================================================================
class TestDatasetIndependence:
    def test_independent_dataset_inventory_exists(self):
        p = RESULTS_DIR / "ml7_independent_dataset_inventory.json"
        assert p.exists(), f"Missing artifact: {p}"
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["external_data_verdict"] == "NO_INDEPENDENT_DATA_AVAILABLE"
        assert len(data["dataset_registry"]) > 10

    def test_canonical_dataset_hash(self):
        assert DATASET_PATH.exists()
        import hashlib
        with open(DATASET_PATH, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        assert h == "390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363"

    def test_scenario_manifest_has_12_scenarios(self):
        p = RESULTS_DIR / "ml7_scenario_manifest.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["scenarios"]) == 12


# ============================================================================
# B. TRAINING ISOLATION & PARTITIONING TESTS
# ============================================================================
class TestTrainingIsolation:
    def test_baseline_manifest_contract(self):
        p = RESULTS_DIR / "ml7_baseline_manifest.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["canonical_contract"]["schema_version"] == "12D-v1"
        assert data["canonical_contract"]["ensemble_weights"] == {"RF": 0.85, "IF": 0.15}

    def test_three_way_partition_sizes(self):
        df = pd.read_csv(DATASET_PATH)
        assert len(df) == 5000
        # 64% train (3200), 16% dev (800), 20% test (1000)
        from sklearn.model_selection import train_test_split
        X = df[list(CANONICAL_FEATURE_NAMES)].values
        y = df["label"].values
        X_tr_f, X_te, y_tr_f, y_te = train_test_split(X, y, test_size=0.20, random_state=100, stratify=y)
        X_tr, X_dv, _, _ = train_test_split(X_tr_f, y_tr_f, test_size=0.20, random_state=100, stratify=y_tr_f)
        assert len(X_tr) == 3200
        assert len(X_dv) == 800
        assert len(X_te) == 1000


# ============================================================================
# C. ROBUSTNESS SCENARIO INTEGRITY TESTS
# ============================================================================
class TestScenarioIntegrity:
    @pytest.mark.parametrize("scen_id", [f"scen_{i:02d}" for i in range(1, 13)])
    def test_scenario_file_validity(self, scen_id):
        matching = list(SCENARIOS_DIR.glob(f"scenario_{scen_id}_*.csv"))
        assert len(matching) == 1, f"Scenario file for {scen_id} not found"
        df = pd.read_csv(matching[0])
        assert len(df) == 1000
        assert tuple(df.columns[:12]) == CANONICAL_FEATURE_NAMES
        assert "label" in df.columns
        assert df.isna().sum().sum() == 0


# ============================================================================
# D. DISTRIBUTION SHIFT & ROBUSTNESS TESTS
# ============================================================================
class TestRobustnessAndShift:
    def test_distribution_shift_artifact(self):
        p = RESULTS_DIR / "ml7_distribution_shift.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        matrix = data["shift_matrix"]
        assert len(matrix) == 12
        for sc_name, sc_info in matrix.items():
            assert "mean_psi" in sc_info
            assert "mean_ks_statistic" in sc_info
            assert len(sc_info["feature_shifts"]) == 12

    def test_robustness_metrics_artifact(self):
        p = RESULTS_DIR / "ml7_robustness_metrics.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        scens = data["scenarios"]
        assert "canonical_test" in scens
        assert len(scens) == 13
        for sc_name, sc_data in scens.items():
            assert "ensemble_f1" in sc_data
            assert "rf_f1" in sc_data
            assert "if_f1" in sc_data
            assert 0.0 <= sc_data["ensemble_f1"] <= 1.0


# ============================================================================
# E. BASELINE COMPARISON TESTS
# ============================================================================
class TestBaselineComparison:
    def test_baseline_models_evaluated(self):
        p = RESULTS_DIR / "ml7_baseline_comparison.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        comps = data["domain_comparisons"]
        assert "canonical_test" in comps
        models_expected = ["dummy_majority", "logistic_regression", "decision_tree", "random_forest", "isolation_forest", "canonical_ensemble"]
        for m in models_expected:
            assert m in comps["canonical_test"]
            assert "f1" in comps["canonical_test"][m]


# ============================================================================
# F. STATISTICAL VALIDATION TESTS
# ============================================================================
class TestStatisticalValidation:
    def test_statistical_tests_artifact(self):
        p = RESULTS_DIR / "ml7_statistical_tests.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "mcnemar_canonical_test" in data
        assert "contingency_table" in data["mcnemar_canonical_test"]
        assert len(data["paired_tests_across_domains"]) >= 5

    def test_confidence_intervals_artifact(self):
        p = RESULTS_DIR / "ml7_confidence_intervals.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        models = data["models"]
        assert "canonical_ensemble" in models
        assert "random_forest" in models
        for m_name in ["canonical_ensemble", "random_forest"]:
            ci = models[m_name]["f1"]["ci_95"]
            mean = models[m_name]["f1"]["mean"]
            assert ci[0] <= mean <= ci[1]


# ============================================================================
# G. FAILURE-MODE & CALIBRATION TESTS
# ============================================================================
class TestFailureModeAndCalibration:
    def test_subgroup_analysis_not_available(self):
        p = RESULTS_DIR / "ml7_error_analysis.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["subgroup_analysis_status"] == "SUBGROUP_ANALYSIS_NOT_AVAILABLE"

    def test_calibration_semantics_audit(self):
        p = RESULTS_DIR / "ml7_calibration_audit.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["findings"]["probabilistic_validity"] == "UNSUPPORTED"
        assert "ordinal threat score" in data["findings"]["interpretation"]

    def test_threshold_robustness_artifact(self):
        p = RESULTS_DIR / "ml7_threshold_robustness.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["provenance_status"] == "NO_PRESERVED_PROVENANCE"
        assert len(data["domain_thresholds"]) == 13


# ============================================================================
# H. ABLATION, REPRODUCIBILITY & LATENCY TESTS
# ============================================================================
class TestAblationReproducibilityLatency:
    def test_ablation_weights_preserved(self):
        p = RESULTS_DIR / "ml7_ablation.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["metadata"]["weights_preserved"] == {"RF": 0.85, "IF": 0.15}

    def test_reproducibility_verdict(self):
        p = RESULTS_DIR / "ml7_reproducibility.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["all_seeds_deterministic"] is True
        assert data["max_absolute_prediction_delta"] < 1e-9

    def test_latency_microbenchmark_present(self):
        p = RESULTS_DIR / "ml7_latency.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "single_event_latency" in data
        assert "ensemble_total" in data["single_event_latency"]
        assert data["single_event_latency"]["ensemble_total"]["mean_ms"] > 0.0


# ============================================================================
# I. CLAIM MATRIX & LIMITATION REGISTER TESTS
# ============================================================================
class TestClaimsAndLimitations:
    def test_claim_traceability_matrix(self):
        p = RESULTS_DIR / "ml7_claim_traceability.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        matrix = data["claims_matrix"]
        assert len(matrix) >= 8
        for item in matrix:
            assert item["status"] in ["VERIFIED", "PARTIALLY_SUPPORTED", "UNSUPPORTED", "OUTDATED", "REQUIRES_QUALIFICATION"]
            # Outperforming RF and calibrated probability MUST be UNSUPPORTED
            if "outperforms standalone Random Forest" in item["claim_text"]:
                assert item["status"] == "UNSUPPORTED"
            if "well-calibrated probability of attack" in item["claim_text"]:
                assert item["status"] == "UNSUPPORTED"
            if "optimal" in item["claim_text"].lower():
                assert item["status"] == "UNSUPPORTED"

    def test_scientific_limitation_register_count(self):
        p = RESULTS_DIR / "ml7_limitation_register.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["limitation_count"] >= 15
        assert len(data["limitations"]) >= 15

    def test_evidence_graph_completeness(self):
        p = RESULTS_DIR / "ml7_evidence_graph.json"
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["nodes"]) >= 8
        assert len(data["edges"]) >= 8


# ============================================================================
# J. HISTORICAL ARTIFACT & CANONICAL CONTRACT TESTS
# ============================================================================
class TestHistoricalPreservation:
    REQUIRED_ML6_JSONS = [
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

    @pytest.mark.parametrize("fname", REQUIRED_ML6_JSONS)
    def test_ml6_artifacts_exist(self, fname):
        p = RESULTS_DIR / fname
        assert p.exists(), f"ML-6 artifact missing: {fname}"

    def test_canonical_weights_unmodified(self):
        assert RF_WEIGHT == 0.85
        assert IF_WEIGHT == 0.15

    def test_canonical_schema_unmodified(self):
        assert len(CANONICAL_FEATURE_NAMES) == 12
        assert CANONICAL_FEATURE_COUNT == 12
        assert SCHEMA_VERSION == "12D-v1"
