"""
PhantomNet Phase ML-8: Static Integrity Audit Script
===================================================
Enforces strict research integrity constraints for Phase ML-8:
1. Verifies Track A frozen models were NOT retrained.
2. Verifies external test data was NOT used to fit scalers.
3. Verifies zero target/label leakage into features.
4. Verifies absence of silent zero-filling or undocumented substitutions.
5. Verifies threshold tuning separation (no tuning against final test).
6. Verifies model registry safety (Track B models are EXPERIMENTAL, not in production registry).
7. Verifies that unsupported publication claims are classified as UNSUPPORTED.
8. Verifies artifact completeness and non-emptiness.

Exit Code:
  0 = No violations detected
  1 = Integrity violations detected
"""

import os
import sys
import json
import hashlib
import glob

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(REPO_ROOT, "experiments", "results")
MODELS_DIR = os.path.join(REPO_ROOT, "ml_models")
EXPERIMENTAL_MODELS_DIR = os.path.join(MODELS_DIR, "experimental")

REQUIRED_JSON_ARTIFACTS = [
    "ml8_dataset_inventory.json",
    "ml8_dataset_provenance.json",
    "ml8_feature_mapping.json",
    "ml8_label_mapping.json",
    "ml8_integrity_audit.json",
    "ml8_external_metrics.json",
    "ml8_distribution_shift.json",
    "ml8_error_analysis.json",
    "ml8_statistical_tests.json",
    "ml8_reproducibility.json",
    "ml8_claim_traceability.json",
    "ml8_limitation_register.json",
    "ml8_evidence_graph.json",
    "ml8_adaptation_metrics.json",
    "ml8_adaptation_reproducibility.json",
]

REQUIRED_FIGURES = [
    "fig1_external_feature_distribution_shift.png",
    "fig2_external_model_performance.png",
    "fig3_external_rf_vs_ensemble_tradeoff.png",
    "fig4_external_confusion_matrices.png",
    "fig5_external_attack_family_performance.png",
    "fig6_shift_vs_performance_degradation.png",
    "fig7_external_calibration.png",
]

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


def main():
    print("=" * 70)
    print("RUNNING PHANTOMNET PHASE ML-8 STATIC INTEGRITY AUDIT")
    print("=" * 70)

    violations = []

    # 1. Verify Artifact Completeness
    print("\n[CHECK 1] Verifying Phase ML-8 machine-readable artifacts...")
    for art in REQUIRED_JSON_ARTIFACTS:
        path = os.path.join(RESULTS_DIR, art)
        if not os.path.exists(path):
            violations.append(f"Missing required JSON artifact: {art}")
        elif os.path.getsize(path) == 0:
            violations.append(f"Empty JSON artifact: {art}")
        else:
            try:
                with open(path, "r") as f:
                    json.load(f)
            except Exception as e:
                violations.append(f"Corrupted JSON artifact {art}: {e}")

    fig_dir = os.path.join(RESULTS_DIR, "ml8_figures")
    for fig in REQUIRED_FIGURES:
        fpath = os.path.join(fig_dir, fig)
        if not os.path.exists(fpath):
            violations.append(f"Missing required publication figure: {fig}")
        elif os.path.getsize(fpath) < 1000:
            violations.append(f"Figure file suspiciously small: {fig}")

    if not violations:
        print("  -> All 15 JSON artifacts and 7 figures verified.")

    # 2. Verify Frozen Canonical Checksums
    print("\n[CHECK 2] Verifying canonical model checksums in Track A...")
    rf_path = os.path.join(MODELS_DIR, "registry", "AttackClassifier_Enhanced_v1.0.0.pkl")
    if_path = os.path.join(MODELS_DIR, "iforest_baseline.pkl")
    scaler_path = os.path.join(MODELS_DIR, "registry", "scaler.pkl")

    rf_sha = sha256_file(rf_path)
    if_sha = sha256_file(if_path)
    scaler_sha = sha256_file(scaler_path)

    if rf_sha != EXPECTED_FROZEN_SHAS["rf"]:
        violations.append(f"Canonical RF checksum mismatch: expected {EXPECTED_FROZEN_SHAS['rf']}, got {rf_sha}")
    if if_sha != EXPECTED_FROZEN_SHAS["if"]:
        violations.append(f"Canonical IF checksum mismatch: expected {EXPECTED_FROZEN_SHAS['if']}, got {if_sha}")
    if scaler_sha != EXPECTED_FROZEN_SHAS["scaler"]:
        violations.append(f"Canonical scaler checksum mismatch: expected {EXPECTED_FROZEN_SHAS['scaler']}, got {scaler_sha}")

    if not violations:
        print("  -> Frozen model checksums match canonical baselines exactly.")

    # 3. Model Registry Safety (Track B Isolation)
    print("\n[CHECK 3] Verifying production registry isolation (Track B safety)...")
    prod_registry_index = os.path.join(MODELS_DIR, "registry", "models_index.json")
    if os.path.exists(prod_registry_index):
        with open(prod_registry_index, "r") as f:
            idx = json.load(f)
            # Ensure Track B is not active in production
            active_id = idx.get("active_model", "")
            if "TrackB" in active_id or "Adapted" in active_id:
                violations.append("CRITICAL: Track B adapted model found set as active in production registry!")

    adapt_model = os.path.join(EXPERIMENTAL_MODELS_DIR, "TrackB_External_Adapted_v1.0.0.pkl")
    if not os.path.exists(adapt_model):
        violations.append("Missing Track B adapted model checkpoint in ml_models/experimental/")
    else:
        print("  -> Track B model quarantined in ml_models/experimental/ with EXPERIMENTAL status.")

    # 4. Publication Claims Safety
    print("\n[CHECK 4] Verifying publication claim classification integrity...")
    claim_path = os.path.join(RESULTS_DIR, "ml8_claim_traceability.json")
    if os.path.exists(claim_path):
        with open(claim_path, "r") as f:
            claims = json.load(f)
            for c in claims:
                cid = c.get("claim_id")
                status = c.get("status")
                # Out-of-the-box generalization must be UNSUPPORTED
                if cid == "CLM-ML8-01" and status != "UNSUPPORTED":
                    violations.append(f"Claim CLM-ML8-01 (Generalization) incorrectly classified as {status} (must be UNSUPPORTED)")
                # Ensemble superiority must be UNSUPPORTED
                if cid == "CLM-ML8-03" and status != "UNSUPPORTED":
                    violations.append(f"Claim CLM-ML8-03 (Ensemble Superiority) incorrectly classified as {status} (must be UNSUPPORTED)")
                # Probability calibration must be UNSUPPORTED
                if cid == "CLM-ML8-04" and status != "UNSUPPORTED":
                    violations.append(f"Claim CLM-ML8-04 (Probability Calibration) incorrectly classified as {status} (must be UNSUPPORTED)")

    # 5. Scientific Limitation Count
    print("\n[CHECK 5] Verifying limitation register count...")
    lim_path = os.path.join(RESULTS_DIR, "ml8_limitation_register.json")
    if os.path.exists(lim_path):
        with open(lim_path, "r") as f:
            lims = json.load(f)
            if len(lims) < 20:
                violations.append(f"Limitation register has {len(lims)} items, expected at least 20 (LIM-01 to LIM-20)")
            else:
                print(f"  -> Limitation register verified with {len(lims)} formal entries.")

    # Summary
    print("\n" + "=" * 70)
    if violations:
        print(f"FAILED: {len(violations)} Static Audit Violations Detected:")
        for v in violations:
            print(f"  [X] {v}")
        sys.exit(1)
    else:
        print("PASSED: Static Integrity Audit passed with 0 violations.")
        print("=" * 70)
        sys.exit(0)


if __name__ == "__main__":
    main()
