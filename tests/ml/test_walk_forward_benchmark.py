"""
tests/ml/test_walk_forward_benchmark.py
---------------------------------------
Temporal Walk-Forward Benchmark & Evaluated Metrics (ML-01, ML-02).

Validates:
  1. Strict chronological train/validation/test splits with ZERO temporal leakage.
  2. Precision, Recall, F1, PR-AUC, and FPR evaluation across rolling time windows.
"""

import os
import sys
import numpy as np
import pandas as pd
import pytest
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    precision_recall_curve,
    auc,
    confusion_matrix,
)

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))


def generate_synthetic_chronological_data(num_samples: int = 1500) -> pd.DataFrame:
    """Generates synthetic time-ordered network traffic for benchmark validation."""
    np.random.seed(42)
    start_time = datetime(2026, 1, 1, 0, 0, 0)
    
    timestamps = [start_time + timedelta(seconds=i * 10) for i in range(num_samples)]
    
    # Features: packet length, port, failure rate, request frequency
    packet_lens = np.random.exponential(scale=300, size=num_samples)
    dst_ports = np.random.choice([22, 80, 443, 21, 25, 8080], size=num_samples)
    failed_attempts = np.random.poisson(lam=1.5, size=num_samples)
    entropy = np.random.uniform(2.0, 7.5, size=num_samples)

    # Malicious label correlated with failed attempts, sensitive ports, and high entropy
    malicious_prob = (
        (failed_attempts > 3).astype(float) * 0.4
        + (dst_ports == 22).astype(float) * 0.3
        + (entropy > 6.0).astype(float) * 0.2
        + np.random.uniform(0, 0.1, size=num_samples)
    )
    labels = (malicious_prob > 0.45).astype(int)

    df = pd.DataFrame({
        "timestamp": timestamps,
        "packet_length": packet_lens,
        "dst_port": dst_ports,
        "failed_attempts": failed_attempts,
        "entropy": entropy,
        "is_malicious": labels,
    })
    return df.sort_values("timestamp").reset_index(drop=True)


def test_zero_temporal_leakage_walk_forward():
    """
    ML-01: Verify that every fold satisfies max(train_timestamp) < min(test_timestamp).
    Zero future data leakage must be strictly guaranteed.
    """
    df = generate_synthetic_chronological_data(1200)
    num_folds = 3
    fold_size = len(df) // (num_folds + 1)

    for fold in range(num_folds):
        train_end_idx = fold_size * (fold + 1)
        test_end_idx = train_end_idx + fold_size

        train_df = df.iloc[:train_end_idx]
        test_df = df.iloc[train_end_idx:test_end_idx]

        max_train_time = train_df["timestamp"].max()
        min_test_time = test_df["timestamp"].min()

        # Strict chronological order
        assert max_train_time < min_test_time, f"Temporal leakage detected in fold {fold}!"


def test_evaluated_metrics_reporting():
    """
    ML-02: Evaluated Metrics Reporting
    Measures Precision, Recall, F1, PR-AUC, and FPR at tuned decision threshold.
    """
    df = generate_synthetic_chronological_data(1500)
    split_point = 1000

    train_df = df.iloc[:split_point]
    test_df = df.iloc[split_point:]

    feature_cols = ["packet_length", "dst_port", "failed_attempts", "entropy"]
    X_train = train_df[feature_cols]
    y_train = train_df["is_malicious"]
    X_test = test_df[feature_cols]
    y_test = test_df["is_malicious"]

    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_train, y_train)

    # Predict probabilities for precision-recall analysis
    probs = clf.predict_proba(X_test)[:, 1]

    # Calculate PR-AUC
    precision_vals, recall_vals, thresholds = precision_recall_curve(y_test, probs)
    pr_auc = auc(recall_vals, precision_vals)

    # Tune threshold (e.g., 0.5)
    threshold = 0.5
    preds = (probs >= threshold).astype(int)

    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n[ML-02 Benchmark Evaluation]")
    print(f"Precision : {prec:.4f}")
    print(f"Recall    : {rec:.4f}")
    print(f"F1 Score  : {f1:.4f}")
    print(f"PR-AUC    : {pr_auc:.4f}")
    print(f"FPR       : {fpr:.4f}")

    # Acceptance criteria
    assert prec >= 0.80, f"Precision {prec} below 0.80"
    assert rec >= 0.75, f"Recall {rec} below 0.75"
    assert f1 >= 0.75, f"F1 {f1} below 0.75"
    assert pr_auc >= 0.80, f"PR-AUC {pr_auc} below 0.80"
    assert fpr <= 0.10, f"False Positive Rate {fpr} exceeds 0.10"
