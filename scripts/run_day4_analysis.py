"""
Day 4 Analysis Runner - Model Quality Validation

This script performs the complete Day 4 analysis:
1. Error Analysis on Misclassifications
2. Class Imbalance Assessment
3. Cross-Validation Stability Check

Output: Generates data for docs/error_analysis_report.md
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate

# Add project root to path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from backend.ml.error_analysis import (
    analyze_error_distribution,
    generate_error_summary,
    get_error_samples
)
from backend.ml.class_imbalance import (
    compute_class_distribution,
    compute_per_class_metrics,
    assess_imbalance_impact,
    analyze_split_distributions,
    generate_imbalance_report
)
from backend.ml.evaluation import evaluate_classification

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
POSSIBLE_FILES = [
    "week6_test_events_balanced.csv",
    "week6_test_events.csv"
]

CSV_PATH = next(
    (os.path.join(DATA_DIR, f) for f in POSSIBLE_FILES if os.path.exists(os.path.join(DATA_DIR, f))),
    None
)

FEATURE_COLUMNS = ["payload_length"]
LABEL_COLUMN = "is_attack"

ATTACK_EVENTS = {
    "login_failed",
    "sqli_attempt",
    "command",
    "connect",
    "mail_from",
    "rcpt_to",
    "data"
}

# --------------------------------------------------
# MAIN ANALYSIS
# --------------------------------------------------
def load_and_prepare_data():
    """Load Week 6 dataset and prepare features/labels."""
    print(f"[Day4] Loading dataset: {CSV_PATH}")
    df = pd.read_csv(CSV_PATH)
    
    # Ensure payload_length exists
    if "payload_length" not in df.columns:
        df["payload_length"] = df["data"].astype(str).apply(len)
    
    # Create labels
    df["is_attack"] = df["event"].apply(
        lambda x: 1 if str(x).lower() in ATTACK_EVENTS else 0
    )
    
    return df


def run_error_analysis(X_test, y_test, y_pred, y_proba):
    """Task 1: Analyze misclassifications."""
    print("\n" + "=" * 60)
    print("TASK 1: ERROR ANALYSIS ON MISCLASSIFICATIONS")
    print("=" * 60)
    
    analysis = analyze_error_distribution(X_test, y_test, y_pred, y_proba)
    summary = generate_error_summary(analysis)
    print(summary)
    
    # Get sample errors
    fp_samples = get_error_samples(X_test, y_test, y_pred, error_type="fp", max_samples=5)
    fn_samples = get_error_samples(X_test, y_test, y_pred, error_type="fn", max_samples=5)
    
    print("\nSample False Positives:")
    if len(fp_samples) > 0:
        print(fp_samples.to_string())
    else:
        print("  (None)")
    
    print("\nSample False Negatives:")
    if len(fn_samples) > 0:
        print(fn_samples.to_string())
    else:
        print("  (None)")
    
    return analysis


def run_class_imbalance_analysis(y_full, y_train, y_test, y_pred, accuracy):
    """Task 2: Check class imbalance issues."""
    print("\n" + "=" * 60)
    print("TASK 2: CLASS IMBALANCE ANALYSIS")
    print("=" * 60)
    
    # Split distributions
    split_dist = analyze_split_distributions(y_full, y_train, y_test)
    
    print("\nFull Dataset Distribution:")
    for name, stats in split_dist["full_dataset"]["classes"].items():
        print(f"  {name}: {stats['count']} ({stats['percentage']:.1f}%)")
    
    print("\nTrain Split Distribution:")
    for name, stats in split_dist["train_split"]["classes"].items():
        print(f"  {name}: {stats['count']} ({stats['percentage']:.1f}%)")
    
    print("\nTest Split Distribution:")
    for name, stats in split_dist["test_split"]["classes"].items():
        print(f"  {name}: {stats['count']} ({stats['percentage']:.1f}%)")
    
    # Per-class metrics
    per_class = compute_per_class_metrics(y_test, y_pred)
    
    # Impact assessment
    full_dist = split_dist["full_dataset"]
    assessment = assess_imbalance_impact(full_dist, per_class, accuracy)
    
    report = generate_imbalance_report(full_dist, per_class, assessment)
    print("\n" + report)
    
    return {
        "split_distributions": split_dist,
        "per_class_metrics": per_class,
        "assessment": assessment
    }


def run_cross_validation(df, model):
    """Task 3: Validate cross-validation stability."""
    print("\n" + "=" * 60)
    print("TASK 3: CROSS-VALIDATION STABILITY")
    print("=" * 60)
    
    X = df[FEATURE_COLUMNS]
    y = df[LABEL_COLUMN]
    
    # Stratified 5-Fold CV
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    scoring = ['accuracy', 'precision', 'recall', 'f1']
    
    print("\nRunning 5-Fold Stratified Cross-Validation...")
    cv_results = cross_validate(
        model, X, y, 
        cv=cv, 
        scoring=scoring,
        return_train_score=False
    )
    
    # Build results table
    print("\nFold Results:")
    print("-" * 60)
    print(f"{'Fold':<6} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1':<12}")
    print("-" * 60)
    
    fold_data = []
    for i in range(5):
        acc = cv_results['test_accuracy'][i]
        prec = cv_results['test_precision'][i]
        rec = cv_results['test_recall'][i]
        f1 = cv_results['test_f1'][i]
        print(f"{i+1:<6} {acc:<12.4f} {prec:<12.4f} {rec:<12.4f} {f1:<12.4f}")
        fold_data.append({
            "fold": i + 1,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1
        })
    
    print("-" * 60)
    
    # Mean and Std
    metrics_summary = {}
    for metric in ['accuracy', 'precision', 'recall', 'f1']:
        key = f'test_{metric}'
        mean_val = np.mean(cv_results[key])
        std_val = np.std(cv_results[key])
        metrics_summary[metric] = {"mean": mean_val, "std": std_val}
        print(f"{metric.capitalize():<12} Mean: {mean_val:.4f}  Std: {std_val:.4f}")
    
    # Stability verdict
    print("\nSTABILITY VERDICT:")
    print("-" * 40)
    
    max_std = max(m["std"] for m in metrics_summary.values())
    if max_std < 0.05:
        verdict = "STABLE - Low variance across folds"
        stability = "high"
    elif max_std < 0.10:
        verdict = "MODERATELY STABLE - Some variance observed"
        stability = "medium"
    else:
        verdict = "UNSTABLE - High variance, model is data-sensitive"
        stability = "low"
    
    print(f"  Max Std Dev: {max_std:.4f}")
    print(f"  Verdict: {verdict}")
    
    return {
        "fold_results": fold_data,
        "summary": metrics_summary,
        "max_std": max_std,
        "stability": stability,
        "verdict": verdict
    }


def main():
    if CSV_PATH is None:
        print(f"[ERROR] No valid Week 6 CSV found in {DATA_DIR}")
        return None
    
    # Load data
    df = load_and_prepare_data()
    print(f"[Day4] Dataset shape: {df.shape}")
    print(f"[Day4] Label distribution:\n{df['is_attack'].value_counts()}")
    
    # Prepare train/test split
    X = df[FEATURE_COLUMNS]
    y = df[LABEL_COLUMN]
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train model (using same config as Day 2)
    print("\n[Day4] Training RandomForest model...")
    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(X_train, y_train)
    
    # Predictions
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]  # Probability of class 1 (attack)
    
    # Evaluate
    metrics = evaluate_classification(y_test, y_pred)
    print(f"[Day4] Test Metrics: {metrics}")
    
    # Run all analyses
    error_analysis = run_error_analysis(X_test, y_test, y_pred, y_proba)
    imbalance_analysis = run_class_imbalance_analysis(
        y.values, y_train.values, y_test.values, y_pred, metrics["accuracy"]
    )
    cv_analysis = run_cross_validation(df, model)
    
    # Compile final results
    results = {
        "dataset": os.path.basename(CSV_PATH),
        "model": "RandomForestClassifier(n_estimators=200)",
        "test_metrics": metrics,
        "error_analysis": error_analysis,
        "imbalance_analysis": imbalance_analysis,
        "cv_analysis": cv_analysis
    }
    
    # Save JSON for report generation
    output_path = os.path.join(PROJECT_ROOT, "data", "day4_analysis_results.json")
    
    # Convert numpy types to Python types for JSON serialization
    def convert_numpy(obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.int64, np.int32)):
            return int(obj)
        elif isinstance(obj, (np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, dict):
            return {k: convert_numpy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_numpy(i) for i in obj]
        return obj
    
    with open(output_path, 'w') as f:
        json.dump(convert_numpy(results), f, indent=2)
    
    print(f"\n[Day4] Results saved to: {output_path}")
    
    return results


if __name__ == "__main__":
    main()
