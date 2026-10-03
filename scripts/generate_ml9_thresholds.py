"""
PhantomNet Phase ML-9: Track F - Threshold Forensics & Policy Provenance
========================================================================
Implements:
- Full threshold sweep (0.00 to 1.00, step 0.01) on DEVELOPMENT partition (16%).
- Selection of optimal thresholds based on distinct operational objectives:
  1. F1-Optimal
  2. Youden's J Statistic
  3. Min-FPR subject to Recall >= 0.95
  4. Min-FNR subject to FPR <= 0.05
  5. Fixed Historical ALERT=0.50
  6. Fixed Historical BLOCK=0.80
- Strict single evaluation on held-out TEST partition (20%).
- Rigorous provenance audit: marks historical constants as NO_PRESERVED_PROVENANCE.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, balanced_accuracy_score

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

from backend.ml.config.feature_schema import CANONICAL_FEATURE_NAMES
from backend.ml.config.thresholds import ALERT_THRESHOLD, BLOCK_THRESHOLD

DATA_DIR = os.path.join(REPO_ROOT, "data", "external_benchmarks")
RESULTS_DIR = os.path.join(REPO_ROOT, "experiments", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

THRESHOLD_GRID = np.linspace(0.0, 1.0, 101)


def get_stratified_split(X: np.ndarray, y: np.ndarray, seed: int = 42) -> Dict[str, Any]:
    indices = np.arange(len(y))
    train_idx, temp_idx = train_test_split(indices, test_size=0.36, random_state=seed, stratify=y)
    dev_idx, test_idx = train_test_split(temp_idx, test_size=0.5555555555555556, random_state=seed, stratify=y[temp_idx])
    return {
        "X_train": X[train_idx],
        "y_train": y[train_idx],
        "X_dev": X[dev_idx],
        "y_dev": y[dev_idx],
        "X_test": X[test_idx],
        "y_test": y[test_idx],
        "train_idx": train_idx,
        "dev_idx": dev_idx,
        "test_idx": test_idx,
    }


def evaluate_threshold_point(y_true: np.ndarray, y_score: np.ndarray, threshold: float) -> Dict[str, Any]:
    y_pred = (y_score >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    youden_j = float(rec - fpr)

    return {
        "threshold": float(threshold),
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
        "balanced_accuracy": bal_acc,
        "youden_j": youden_j,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        }
    }


def run_threshold_forensics(datasets: Dict[str, pd.DataFrame]) -> Dict[str, Any]:
    print("\n--- RUNNING TRACK F: THRESHOLD FORENSICS & PROVENANCE ---", flush=True)
    results = {}

    for name, df in datasets.items():
        X = df[list(CANONICAL_FEATURE_NAMES)].values
        y = df["label"].values.astype(int)

        split = get_stratified_split(X, y, seed=42)
        X_train, y_train = split["X_train"], split["y_train"]
        X_dev, y_dev = split["X_dev"], split["y_dev"]
        X_test, y_test = split["X_test"], split["y_test"]

        # Fit model on training partition only
        rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=1)
        rf.fit(X_train, y_train)

        dev_scores = rf.predict_proba(X_dev)[:, 1]
        test_scores = rf.predict_proba(X_test)[:, 1]

        # 1. Sweep across full grid on DEVELOPMENT set ONLY
        dev_sweep = [evaluate_threshold_point(y_dev, dev_scores, t) for t in THRESHOLD_GRID]

        # 2. Select optimal thresholds based on DEV objectives
        best_f1_item = max(dev_sweep, key=lambda item: item["f1"])
        t_f1_opt = best_f1_item["threshold"]

        best_youden_item = max(dev_sweep, key=lambda item: item["youden_j"])
        t_youden = best_youden_item["threshold"]

        rec_95_candidates = [item for item in dev_sweep if item["recall"] >= 0.95]
        if rec_95_candidates:
            best_min_fpr = min(rec_95_candidates, key=lambda item: item["fpr"])
            t_min_fpr = best_min_fpr["threshold"]
        else:
            t_min_fpr = t_f1_opt

        fpr_05_candidates = [item for item in dev_sweep if item["fpr"] <= 0.05]
        if fpr_05_candidates:
            best_min_fnr = min(fpr_05_candidates, key=lambda item: item["fnr"])
            t_min_fnr = best_min_fnr["threshold"]
        else:
            t_min_fnr = t_f1_opt

        # 3. Evaluate Dev-selected policies on held-out TEST set
        policies = {
            "F1_Optimal_DevSelected": {
                "objective": "Maximize F1 score on development partition",
                "selected_threshold": t_f1_opt,
                "dev_performance": evaluate_threshold_point(y_dev, dev_scores, t_f1_opt),
                "test_performance": evaluate_threshold_point(y_test, test_scores, t_f1_opt),
                "provenance": "EMPIRICALLY_OPTIMIZED_ON_DEV"
            },
            "Youden_J_DevSelected": {
                "objective": "Maximize Youden's J statistic on dev",
                "selected_threshold": t_youden,
                "dev_performance": evaluate_threshold_point(y_dev, dev_scores, t_youden),
                "test_performance": evaluate_threshold_point(y_test, test_scores, t_youden),
                "provenance": "EMPIRICALLY_OPTIMIZED_ON_DEV"
            },
            "Min_FPR_Constrained_Recall95": {
                "objective": "Minimize False Positive Rate subject to Recall >= 0.95 on dev",
                "selected_threshold": t_min_fpr,
                "dev_performance": evaluate_threshold_point(y_dev, dev_scores, t_min_fpr),
                "test_performance": evaluate_threshold_point(y_test, test_scores, t_min_fpr),
                "provenance": "EMPIRICALLY_OPTIMIZED_ON_DEV"
            },
            "Min_FNR_Constrained_FPR05": {
                "objective": "Minimize False Negative Rate subject to FPR <= 0.05 on dev",
                "selected_threshold": t_min_fnr,
                "dev_performance": evaluate_threshold_point(y_dev, dev_scores, t_min_fnr),
                "test_performance": evaluate_threshold_point(y_test, test_scores, t_min_fnr),
                "provenance": "EMPIRICALLY_OPTIMIZED_ON_DEV"
            },
            "Fixed_ALERT_0.50": {
                "objective": "Historical default policy alert threshold",
                "selected_threshold": 0.50,
                "dev_performance": evaluate_threshold_point(y_dev, dev_scores, 0.50),
                "test_performance": evaluate_threshold_point(y_test, test_scores, 0.50),
                "provenance": "NO_PRESERVED_PROVENANCE"
            },
            "Fixed_BLOCK_0.80": {
                "objective": "Historical default policy block threshold",
                "selected_threshold": 0.80,
                "dev_performance": evaluate_threshold_point(y_dev, dev_scores, 0.80),
                "test_performance": evaluate_threshold_point(y_test, test_scores, 0.80),
                "provenance": "NO_PRESERVED_PROVENANCE"
            }
        }

        results[name] = {
            "policies": policies,
            "dev_sweep_summary": {
                "thresholds": [p["threshold"] for p in dev_sweep],
                "f1_curve": [p["f1"] for p in dev_sweep],
                "fpr_curve": [p["fpr"] for p in dev_sweep],
                "recall_curve": [p["recall"] for p in dev_sweep],
                "precision_curve": [p["precision"] for p in dev_sweep],
            },
            "forensic_determination": (
                f"On {name}, dev-optimal F1 threshold is {t_f1_opt:.2f}. "
                f"Fixed historical 0.50 achieves F1={policies['Fixed_ALERT_0.50']['test_performance']['f1']:.4f} "
                f"while 0.80 achieves F1={policies['Fixed_BLOCK_0.80']['test_performance']['f1']:.4f} on test. "
                "The 0.50 and 0.80 thresholds represent uncalibrated heuristic policy cutoffs with NO_PRESERVED_PROVENANCE."
            )
        }

    return results


def main():
    datasets = {
        "Synthetic": pd.read_csv(os.path.join(REPO_ROOT, "data", "remediated_dataset_v3.csv")),
        "NF-ToN-IoT-v2": pd.read_csv(os.path.join(DATA_DIR, "nf_ton_iot_v2_canonical_12d.csv")),
        "CIC-IDS2017": pd.read_csv(os.path.join(DATA_DIR, "cicids2017_canonical_12d.csv")),
        "UNSW-NB15": pd.read_csv(os.path.join(DATA_DIR, "unsw_nb15_canonical_12d.csv")),
    }

    forensics = run_threshold_forensics(datasets)

    out_file = os.path.join(RESULTS_DIR, "ml9_thresholds.json")
    with open(out_file, "w") as f:
        json.dump(forensics, f, indent=2)
    print(f"[PASS] Saved threshold forensics to: {out_file}", flush=True)


if __name__ == "__main__":
    main()
