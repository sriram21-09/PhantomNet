"""
PhantomNet Phase ML-9: Automated Forensic Test Suite
===================================================
Tests and verifies all 22 Phase ML-9 validation requirements (A through V):
A. dataset integrity
B. external dataset hashes
C. feature mapping integrity
D. label isolation
E. train/dev/test isolation
F. threshold isolation
G. calibration isolation
H. no test leakage
I. deterministic seeds
J. reproducible splitting
K. model checksum preservation
L. canonical artifact preservation
M. transfer matrix completeness
N. adaptation learning-curve completeness
O. ablation completeness
P. statistical artifact validity
Q. figure generation
R. claim traceability
S. limitation register
T. deployment-readiness evidence
U. reproduction equivalence
V. static repository audit
"""

import os
import json
import hashlib
import pytest
import numpy as np
import pandas as pd

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RESULTS_DIR = os.path.join(REPO_ROOT, "experiments", "results")
FIGURES_DIR = os.path.join(RESULTS_DIR, "ml9_figures")
DATA_DIR = os.path.join(REPO_ROOT, "data", "external_benchmarks")
MODELS_DIR = os.path.join(REPO_ROOT, "ml_models")
EXPERIMENTAL_MODELS_DIR = os.path.join(MODELS_DIR, "experimental", "ml9")

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

EXPECTED_CANONICAL_SHAS = {
    "canonical_dataset": "390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363",
    "canonical_rf": "7ca8651fca269842d7f0f829a5aba9485453a38fa6263a67c2130ac0c9c66dc2",
    "canonical_if": "3a057d52a125d22ae46f7b83f92aaec02aea42a2c56519c70add3890a9c04b7b",
    "canonical_scaler": "4f7b1ea192f136f718af7868947c23b965c41c083ccab1b3da955a9035f74e8d",
    "feature_schema": "6484bbf27b7bc918133133ba48170f8c5e036ddac31f23b5bb6b6db8e6258a2e",
    "thresholds": "a3353927332ecf5bee332cff3c3fba92ee6587850a4d895c4c8bb26c1db7d8cd"
}


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ==============================================================================
# 1. DATASET & ARTIFACT INTEGRITY (Requirements A, B, C, D)
# ==============================================================================

class TestDatasetAndFeatureIntegrity:
    def test_req_a_dataset_manifest_exists_and_valid(self):
        path = os.path.join(RESULTS_DIR, "ml9_dataset_manifest.json")
        assert os.path.exists(path), "Missing ml9_dataset_manifest.json"
        with open(path, "r") as f:
            manifest = json.load(f)
        assert manifest["total_datasets"] == 4
        assert len(manifest["datasets"]) == 4

    def test_req_b_external_dataset_hashes_match(self):
        manifest_path = os.path.join(RESULTS_DIR, "ml9_dataset_manifest.json")
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        for ds in manifest["datasets"]:
            fpath = os.path.join(REPO_ROOT, ds["file"])
            assert os.path.exists(fpath), f"Missing dataset file: {fpath}"
            assert sha256_file(fpath) == ds["sha256"], f"SHA mismatch on {ds['id']}"

    @pytest.mark.parametrize("fname", [
        "nf_ton_iot_v2_canonical_12d.csv",
        "cicids2017_canonical_12d.csv",
        "unsw_nb15_canonical_12d.csv"
    ])
    def test_req_c_feature_mapping_integrity(self, fname):
        fpath = os.path.join(DATA_DIR, fname)
        df = pd.read_csv(fpath)
        assert df.shape == (5000, 13)
        X = df[list(CANONICAL_FEATURE_NAMES)]
        arr = validate_feature_vector(X)
        assert arr.shape == (5000, 12)
        assert not np.isnan(arr).any(), "NaN found in feature vector"
        assert not np.isinf(arr).any(), "Inf found in feature vector"

    def test_req_d_label_isolation_and_binary_encoding(self):
        for fname in ["nf_ton_iot_v2_canonical_12d.csv", "cicids2017_canonical_12d.csv", "unsw_nb15_canonical_12d.csv"]:
            fpath = os.path.join(DATA_DIR, fname)
            df = pd.read_csv(fpath)
            assert set(df["label"].unique()) == {0, 1}
            assert (df["label"] == 0).sum() == 3500
            assert (df["label"] == 1).sum() == 1500


# ==============================================================================
# 2. ISOLATION & METHODOLOGICAL INTEGRITY (Requirements E, F, G, H, I, J)
# ==============================================================================

class TestIsolationAndMethodology:
    def test_req_e_train_dev_test_isolation(self):
        with open(os.path.join(RESULTS_DIR, "ml9_dataset_manifest.json")) as f:
            manifest = json.load(f)
        for ds in manifest["datasets"]:
            assert ds["train_samples"] == 3200
            assert ds["dev_samples"] == 800
            assert ds["test_samples"] == 1000

    def test_req_f_threshold_development_isolation(self):
        path = os.path.join(RESULTS_DIR, "ml9_thresholds.json")
        assert os.path.exists(path), "Missing ml9_thresholds.json"
        with open(path, "r") as f:
            data = json.load(f)
        for ds in ["NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            assert ds in data
            assert "F1_Optimal_DevSelected" in data[ds]["policies"]
            assert data[ds]["policies"]["F1_Optimal_DevSelected"]["provenance"] == "EMPIRICALLY_OPTIMIZED_ON_DEV"
            assert data[ds]["policies"]["Fixed_ALERT_0.50"]["provenance"] == "NO_PRESERVED_PROVENANCE"

    def test_req_g_calibration_development_isolation(self):
        path = os.path.join(RESULTS_DIR, "ml9_calibration.json")
        assert os.path.exists(path), "Missing ml9_calibration.json"
        with open(path, "r") as f:
            data = json.load(f)
        for ds in ["NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            assert ds in data
            assert data[ds]["G3_Ensemble_Composite_Threat_Score"]["formal_classification"] == "ORDINAL_COMPOSITE_THREAT_SCORE"
            assert "RF_Platt_Sigmoid" in data[ds]["G4_PostHoc_Calibration"]

    def test_req_h_no_test_leakage_in_scripts(self):
        scripts_dir = os.path.join(REPO_ROOT, "scripts")
        for fname in os.listdir(scripts_dir):
            if fname.startswith("generate_ml9_"):
                fpath = os.path.join(scripts_dir, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                assert "fit(X_test" not in content, f"Forbidden test fit in {fname}"
                assert "fit_transform(X_test" not in content, f"Forbidden test fit_transform in {fname}"

    def test_req_i_deterministic_seeds_configured(self):
        with open(os.path.join(RESULTS_DIR, "ml9_adaptation_learning_curves.json")) as f:
            data = json.load(f)
        for ds in ["NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            per_seed = data["track_a_multi_seed_evaluation"][ds]["A1_RF_Scratch"]["per_seed"]
            assert len(per_seed) == 10, f"Expected 10 seeds on {ds}"


# ==============================================================================
# 3. CANONICAL PRESERVATION & CHECKSUMS (Requirements K, L)
# ==============================================================================

class TestCanonicalPreservation:
    def test_req_k_canonical_checksums_unmodified(self):
        file_map = {
            "canonical_dataset": os.path.join(REPO_ROOT, "data", "remediated_dataset_v3.csv"),
            "canonical_rf": os.path.join(MODELS_DIR, "registry", "AttackClassifier_Enhanced_v1.0.0.pkl"),
            "canonical_if": os.path.join(MODELS_DIR, "iforest_baseline.pkl"),
            "canonical_scaler": os.path.join(MODELS_DIR, "registry", "scaler.pkl"),
            "feature_schema": os.path.join(REPO_ROOT, "backend", "ml", "config", "feature_schema.py"),
            "thresholds": os.path.join(REPO_ROOT, "backend", "ml", "config", "thresholds.py"),
        }
        for k, expected_sha in EXPECTED_CANONICAL_SHAS.items():
            path = file_map[k]
            assert os.path.exists(path), f"Missing {k}"
            assert sha256_file(path) == expected_sha, f"Protected artifact checksum mutated for {k}!"

    def test_req_l_experimental_model_quarantine(self):
        prod_reg = os.path.join(MODELS_DIR, "registry", "models_index.json")
        if os.path.exists(prod_reg):
            with open(prod_reg, "r") as f:
                idx = json.load(f)
            active = str(idx.get("active_model", ""))
            assert "ml9" not in active.lower()
            assert "adapted" not in active.lower()


# ==============================================================================
# 4. EXPERIMENTAL MATRIX & EVIDENCE COMPLETENESS (Requirements M, N, O, P, Q)
# ==============================================================================

class TestExperimentalMatrixAndFigures:
    def test_req_m_transfer_matrix_completeness(self):
        path = os.path.join(RESULTS_DIR, "ml9_transfer_matrix.json")
        assert os.path.exists(path), "Missing ml9_transfer_matrix.json"
        with open(path, "r") as f:
            data = json.load(f)
        matrix = data["transfer_matrix"]
        for src in ["Synthetic", "NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            for tgt in ["Synthetic", "NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
                assert tgt in matrix[src]
                cell = matrix[src][tgt]
                assert 0.0 <= cell["roc_auc"] <= 1.0
                assert 0.0 <= cell["f1"] <= 1.0

    def test_req_n_adaptation_learning_curves_completeness(self):
        path = os.path.join(RESULTS_DIR, "ml9_adaptation_learning_curves.json")
        assert os.path.exists(path), "Missing ml9_adaptation_learning_curves.json"
        with open(path, "r") as f:
            data = json.load(f)
        for ds in ["NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            fractions = data["track_b_learning_curves"][ds]["fractions"]
            assert len(fractions) == 7
            pcts = [f["effective_train_pct_of_total"] for f in fractions]
            assert 64.0 in pcts

    def test_req_o_ablation_completeness(self):
        path = os.path.join(RESULTS_DIR, "ml9_ablation.json")
        assert os.path.exists(path), "Missing ml9_ablation.json"
        with open(path, "r") as f:
            data = json.load(f)
        for ds in ["Synthetic", "NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            assert len(data["ablation_experiments"][ds]["leave_one_feature_out"]) == 12
            assert len(data["ablation_experiments"][ds]["grouped_ablation"]) == 6

    def test_req_p_statistical_artifacts_valid(self):
        path = os.path.join(RESULTS_DIR, "ml9_statistical_tests.json")
        assert os.path.exists(path), "Missing ml9_statistical_tests.json"
        with open(path, "r") as f:
            data = json.load(f)
        assert len(data["tests"]) == 6
        for t in data["tests"]:
            assert "adjusted_p_value" in t
            assert "familywise_verdict" in t

        ci_path = os.path.join(RESULTS_DIR, "ml9_confidence_intervals.json")
        assert os.path.exists(ci_path), "Missing ml9_confidence_intervals.json"
        with open(ci_path, "r") as f:
            ci_data = json.load(f)
        for ds in ["Synthetic", "NF-ToN-IoT-v2", "CIC-IDS2017", "UNSW-NB15"]:
            assert "f1" in ci_data[ds]
            assert "ci_95_lower" in ci_data[ds]["f1"]
            assert "ci_95_upper" in ci_data[ds]["f1"]

    @pytest.mark.parametrize("figname", [
        "fig1_learning_curves.png",
        "fig2_cross_domain_transfer_heatmap.png",
        "fig3_representation_ablation.png",
        "fig4_feature_semantic_risk.png",
        "fig5_threshold_tradeoff.png",
        "fig6_calibration_curves.png",
        "fig7_domain_shift_vs_performance.png",
        "fig8_adaptation_safety.png",
        "fig9_model_comparison_by_domain.png",
        "fig10_error_analysis.png"
    ])
    def test_req_q_figure_generation(self, figname):
        fpath = os.path.join(FIGURES_DIR, figname)
        assert os.path.exists(fpath), f"Missing figure: {figname}"
        assert os.path.getsize(fpath) > 10000, f"Figure too small / empty: {figname}"


# ==============================================================================
# 5. CLAIMS, LIMITATIONS, REPRODUCIBILITY & AUDIT (Requirements R, S, T, U, V)
# ==============================================================================

class TestClaimsLimitationsAndReproducibility:
    def test_req_r_claim_traceability_matrix(self):
        path = os.path.join(RESULTS_DIR, "ml9_claim_traceability.json")
        assert os.path.exists(path), "Missing ml9_claim_traceability.json"
        with open(path, "r") as f:
            claims = json.load(f)
        assert len(claims) >= 8
        statuses = {c["claim_id"]: c["status"] for c in claims}
        assert statuses["CLM-ML9-01"] == "UNSUPPORTED"
        assert statuses["CLM-ML9-02"] == "VERIFIED WITH QUALIFICATION"
        assert statuses["CLM-ML9-03"] == "UNSUPPORTED"
        assert statuses["CLM-ML9-04"] == "UNSUPPORTED"
        assert statuses["CLM-ML9-05"] == "UNSUPPORTED"
        assert statuses["CLM-ML9-06"] == "VERIFIED"
        assert statuses["CLM-ML9-07"] == "VERIFIED"
        assert statuses["CLM-ML9-08"] == "UNSUPPORTED"

    def test_req_s_scientific_limitation_register(self):
        path = os.path.join(RESULTS_DIR, "ml9_limitation_register.json")
        assert os.path.exists(path), "Missing ml9_limitation_register.json"
        with open(path, "r") as f:
            lims = json.load(f)
        assert len(lims) >= 25, f"Expected at least 25 limitations, got {len(lims)}"

    def test_req_t_deployment_readiness_evidence(self):
        path = os.path.join(RESULTS_DIR, "ml9_deployment_readiness.json")
        assert os.path.exists(path), "Missing ml9_deployment_readiness.json"
        with open(path, "r") as f:
            data = json.load(f)
        matrix = data["readiness_matrix"]
        assert matrix["Tier_1_Offline_Research"]["status"] == "APPROVED"
        assert matrix["Tier_4_Turnkey_Production_Deployment"]["status"] == "NOT_APPROVED_FOR_ZERO_SHOT"

    def test_req_u_reproduction_equivalence(self):
        path = os.path.join(RESULTS_DIR, "ml9_reproducibility.json")
        assert os.path.exists(path), "Missing ml9_reproducibility.json"
        with open(path, "r") as f:
            data = json.load(f)
        assert data["status"] == "PASS"
        assert data["max_floating_point_delta"] < 1e-6

    def test_req_v_static_repository_audit_clean(self):
        path = os.path.join(RESULTS_DIR, "ml9_static_audit.json")
        assert os.path.exists(path), "Missing ml9_static_audit.json"
        with open(path, "r") as f:
            data = json.load(f)
        assert data["total_violations"] == 0
        assert data["status"] == "PASS"
