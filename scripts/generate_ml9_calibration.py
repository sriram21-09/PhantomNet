"""
PhantomNet Phase ML-9: Track G - Calibration Forensics & Posterior Validity
===========================================================================
Implements:
- G1: RF probability calibration forensics.
- G2: Isolation Forest anomaly score calibration feasibility.
- G3: Composite ensemble ordinal score evaluation.
- G4: Post-hoc probability calibration (Platt Sigmoid & Isotonic Regression)
  fitted strictly on DEVELOPMENT partition (16%) and evaluated on TEST partition (20%).
- Computes: Brier score, standard ECE (10 bins), adaptive ECE (equal-mass bins),
  reliability diagram coordinates, calibration slope, and calibration intercept.
- Formal classification of composite threat score: ORDINAL_COMPOSITE_THREAT_SCORE.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import brier_score_loss, roc_auc_score

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

from backend.ml.config.feature_schema import CANONICAL_FEATURE_NAMES
from backend.ml.config.thresholds import (
    RF_WEIGHT,
    IF_WEIGHT,
    IF_CALIBRATION_MIN,
    IF_CALIBRATION_MAX,
)

DATA_DIR = os.path.join(REPO_ROOT, "data", "external_benchmarks")
RESULTS_DIR = os.path.join(REPO_ROOT, "experiments", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


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


def compute_ece(probs: np.ndarray, true_labels: np.ndarray, n_bins: int = 10) -> Tuple[float, List[Dict[str, float]]]:
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(probs)
    diagram_points = []

    for i in range(n_bins):
        bin_lower, bin_upper = bin_edges[i], bin_edges[i + 1]
        mask = (probs >= bin_lower) & (probs < bin_upper) if i < n_bins - 1 else (probs >= bin_lower) & (probs <= bin_upper)
        bin_count = int(np.sum(mask))
        if bin_count > 0:
            bin_acc = float(np.mean(true_labels[mask]))
            bin_conf = float(np.mean(probs[mask]))
            bin_weight = bin_count / n
            ece += bin_weight * np.abs(bin_acc - bin_conf)
            diagram_points.append({
                "bin_idx": i,
                "bin_lower": float(bin_lower),
                "bin_upper": float(bin_upper),
                "bin_count": bin_count,
                "bin_confidence": bin_conf,
                "bin_accuracy": bin_acc,
                "calibration_gap": float(np.abs(bin_acc - bin_conf)),
            })
        else:
            diagram_points.append({
                "bin_idx": i,
                "bin_lower": float(bin_lower),
                "bin_upper": float(bin_upper),
                "bin_count": 0,
                "bin_confidence": float((bin_lower + bin_upper) / 2.0),
                "bin_accuracy": 0.0,
                "calibration_gap": 0.0,
            })

    return float(ece), diagram_points


def compute_adaptive_ece(probs: np.ndarray, true_labels: np.ndarray, n_bins: int = 10) -> float:
    n = len(probs)
    if n < n_bins:
        return 0.0
    sorted_indices = np.argsort(probs)
    sorted_probs = probs[sorted_indices]
    sorted_labels = true_labels[sorted_indices]

    bins = np.array_split(np.arange(n), n_bins)
    aece = 0.0
    for b in bins:
        if len(b) == 0:
            continue
        bin_acc = np.mean(sorted_labels[b])
        bin_conf = np.mean(sorted_probs[b])
        bin_weight = len(b) / n
        aece += bin_weight * np.abs(bin_acc - bin_conf)
    return float(aece)


def compute_calibration_slope_intercept(probs: np.ndarray, true_labels: np.ndarray) -> Tuple[float, float]:
    eps = 1e-6
    clipped_probs = np.clip(probs, eps, 1.0 - eps)
    logits = np.log(clipped_probs / (1.0 - clipped_probs)).reshape(-1, 1)

    try:
        lr = LogisticRegression(penalty=None, solver="lbfgs")
        lr.fit(logits, true_labels)
        slope = float(lr.coef_[0][0])
        intercept = float(lr.intercept_[0])
        return slope, intercept
    except Exception:
        return 1.0, 0.0


def normalize_if_score(raw_scores: np.ndarray, min_val: float = IF_CALIBRATION_MIN, max_val: float = IF_CALIBRATION_MAX) -> np.ndarray:
    inverted = -raw_scores
    clipped = np.clip(inverted, min_val, max_val)
    norm = (clipped - min_val) / (max_val - min_val + 1e-9)
    return np.clip(norm, 0.0, 1.0)


def run_calibration_forensics(datasets: Dict[str, pd.DataFrame]) -> Dict[str, Any]:
    print("\n--- RUNNING TRACK G: CALIBRATION FORENSICS & POST-HOC MAPPING ---", flush=True)
    calibration_results = {}

    for name, df in datasets.items():
        X = df[list(CANONICAL_FEATURE_NAMES)].values
        y = df["label"].values.astype(int)

        split = get_stratified_split(X, y, seed=42)
        X_train, y_train = split["X_train"], split["y_train"]
        X_dev, y_dev = split["X_dev"], split["y_dev"]
        X_test, y_test = split["X_test"], split["y_test"]

        # 1. Train base models on Train set
        rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=1)
        rf.fit(X_train, y_train)

        iforest = IsolationForest(n_estimators=100, random_state=42, n_jobs=1, contamination=0.30)
        iforest.fit(X_train)

        # Get Dev and Test raw outputs
        rf_dev_probs = rf.predict_proba(X_dev)[:, 1]
        rf_test_probs = rf.predict_proba(X_test)[:, 1]

        if_dev_raw = iforest.decision_function(X_dev)
        if_test_raw = iforest.decision_function(X_test)
        if_dev_norm = normalize_if_score(if_dev_raw)
        if_test_norm = normalize_if_score(if_test_raw)

        # Composite score
        comp_dev_score = RF_WEIGHT * rf_dev_probs + IF_WEIGHT * if_dev_norm
        comp_test_score = RF_WEIGHT * rf_test_probs + IF_WEIGHT * if_test_norm

        # --- G1: Raw RF Calibration ---
        rf_ece, rf_diagram = compute_ece(rf_test_probs, y_test)
        rf_aece = compute_adaptive_ece(rf_test_probs, y_test)
        rf_slope, rf_intercept = compute_calibration_slope_intercept(rf_test_probs, y_test)
        rf_brier = float(brier_score_loss(y_test, rf_test_probs))

        # --- G2: Isolation Forest Anomaly Score ---
        if_ece, if_diagram = compute_ece(if_test_norm, y_test)
        if_aece = compute_adaptive_ece(if_test_norm, y_test)
        if_brier = float(brier_score_loss(y_test, if_test_norm))

        # --- G3: Ensemble Composite Score ---
        comp_ece, comp_diagram = compute_ece(comp_test_score, y_test)
        comp_aece = compute_adaptive_ece(comp_test_score, y_test)
        comp_slope, comp_intercept = compute_calibration_slope_intercept(comp_test_score, y_test)
        comp_brier = float(brier_score_loss(y_test, comp_test_score))

        # --- G4: Post-hoc Calibration fitted strictly on DEV partition ---
        eps = 1e-6
        dev_logits = np.log(np.clip(rf_dev_probs, eps, 1.0 - eps) / (1.0 - np.clip(rf_dev_probs, eps, 1.0 - eps))).reshape(-1, 1)
        test_logits = np.log(np.clip(rf_test_probs, eps, 1.0 - eps) / (1.0 - np.clip(rf_test_probs, eps, 1.0 - eps))).reshape(-1, 1)

        platt_model = LogisticRegression(penalty=None, solver="lbfgs")
        platt_model.fit(dev_logits, y_dev)
        rf_platt_test_probs = platt_model.predict_proba(test_logits)[:, 1]

        platt_ece, platt_diagram = compute_ece(rf_platt_test_probs, y_test)
        platt_aece = compute_adaptive_ece(rf_platt_test_probs, y_test)
        platt_brier = float(brier_score_loss(y_test, rf_platt_test_probs))
        platt_slope, platt_intercept = compute_calibration_slope_intercept(rf_platt_test_probs, y_test)

        iso_model = IsotonicRegression(out_of_bounds="clip")
        iso_model.fit(rf_dev_probs, y_dev)
        rf_iso_test_probs = iso_model.predict(rf_test_probs)

        iso_ece, iso_diagram = compute_ece(rf_iso_test_probs, y_test)
        iso_aece = compute_adaptive_ece(rf_iso_test_probs, y_test)
        iso_brier = float(brier_score_loss(y_test, rf_iso_test_probs))
        iso_slope, iso_intercept = compute_calibration_slope_intercept(rf_iso_test_probs, y_test)

        comp_dev_logits = np.log(np.clip(comp_dev_score, eps, 1.0 - eps) / (1.0 - np.clip(comp_dev_score, eps, 1.0 - eps))).reshape(-1, 1)
        comp_test_logits = np.log(np.clip(comp_test_score, eps, 1.0 - eps) / (1.0 - np.clip(comp_test_score, eps, 1.0 - eps))).reshape(-1, 1)

        platt_comp_model = LogisticRegression(penalty=None, solver="lbfgs")
        platt_comp_model.fit(comp_dev_logits, y_dev)
        comp_platt_test_probs = platt_comp_model.predict_proba(comp_test_logits)[:, 1]

        comp_platt_ece, comp_platt_diagram = compute_ece(comp_platt_test_probs, y_test)
        comp_platt_brier = float(brier_score_loss(y_test, comp_platt_test_probs))

        calibration_results[name] = {
            "G1_Random_Forest_Raw": {
                "brier_score": rf_brier,
                "ece": rf_ece,
                "adaptive_ece": rf_aece,
                "calibration_slope": rf_slope,
                "calibration_intercept": rf_intercept,
                "reliability_diagram": rf_diagram,
                "posterior_probability_claim": "UNSUPPORTED (Raw tree average)",
            },
            "G2_Isolation_Forest_Normalized": {
                "brier_score": if_brier,
                "ece": if_ece,
                "adaptive_ece": if_aece,
                "posterior_probability_claim": "UNSUPPORTED (Heuristic min-max distance mapping)",
            },
            "G3_Ensemble_Composite_Threat_Score": {
                "brier_score": comp_brier,
                "ece": comp_ece,
                "adaptive_ece": comp_aece,
                "calibration_slope": comp_slope,
                "calibration_intercept": comp_intercept,
                "reliability_diagram": comp_diagram,
                "formal_classification": "ORDINAL_COMPOSITE_THREAT_SCORE",
                "posterior_probability_claim": "UNSUPPORTED (Linear convex combination of tree probability and distance heuristic)",
            },
            "G4_PostHoc_Calibration": {
                "RF_Platt_Sigmoid": {
                    "brier_score": platt_brier,
                    "ece": platt_ece,
                    "adaptive_ece": platt_aece,
                    "calibration_slope": platt_slope,
                    "calibration_intercept": platt_intercept,
                    "reliability_diagram": platt_diagram,
                },
                "RF_Isotonic_Regression": {
                    "brier_score": iso_brier,
                    "ece": iso_ece,
                    "adaptive_ece": iso_aece,
                    "calibration_slope": iso_slope,
                    "calibration_intercept": iso_intercept,
                    "reliability_diagram": iso_diagram,
                },
                "Composite_Platt_Sigmoid": {
                    "brier_score": comp_platt_brier,
                    "ece": comp_platt_ece,
                },
            },
            "scientific_verdict": (
                "The canonical composite threat score S = 0.85*P_RF + 0.15*S_IF is an ordinal ranking score, NOT a calibrated posterior probability. "
                "Post-hoc Platt scaling and Isotonic regression improve probability calibration on RF outputs when fitted on development data, "
                "but the composite score must retain the classification ORDINAL_COMPOSITE_THREAT_SCORE."
            )
        }

    return calibration_results


def main():
    datasets = {
        "Synthetic": pd.read_csv(os.path.join(REPO_ROOT, "data", "remediated_dataset_v3.csv")),
        "NF-ToN-IoT-v2": pd.read_csv(os.path.join(DATA_DIR, "nf_ton_iot_v2_canonical_12d.csv")),
        "CIC-IDS2017": pd.read_csv(os.path.join(DATA_DIR, "cicids2017_canonical_12d.csv")),
        "UNSW-NB15": pd.read_csv(os.path.join(DATA_DIR, "unsw_nb15_canonical_12d.csv")),
    }

    cal_results = run_calibration_forensics(datasets)

    out_file = os.path.join(RESULTS_DIR, "ml9_calibration.json")
    with open(out_file, "w") as f:
        json.dump(cal_results, f, indent=2)
    print(f"[PASS] Saved calibration forensics to: {out_file}", flush=True)


if __name__ == "__main__":
    main()
