import pandas as pd
import numpy as np
from sklearn.model_selection import KFold, cross_validate
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import os
import joblib


class CrossValidator:
    def __init__(self, n_splits=5):
        self.n_splits = n_splits
        self.kfold = KFold(n_splits=n_splits, shuffle=True, random_state=42)

    def evaluate_model(self, model, X, y, model_name="Model"):
        print(f"🔄 Running {self.n_splits}-Fold Cross-Validation for {model_name}...")

        scoring = ["accuracy", "precision_weighted", "recall_weighted", "f1_weighted"]
        results = cross_validate(model, X, y, cv=self.kfold, scoring=scoring, n_jobs=-1)

        stats = {
            "model_name": model_name,
            "accuracy_mean": np.mean(results["test_accuracy"]),
            "accuracy_std": np.std(results["test_accuracy"]),
            "precision_mean": np.mean(results["test_precision_weighted"]),
            "recall_mean": np.mean(results["test_recall_weighted"]),
            "f1_mean": np.mean(results["test_f1_weighted"]),
            "fold_accuracies": results["test_accuracy"].tolist(),
        }

        print(
            f"✅ {model_name} - Mean Accuracy: {stats['accuracy_mean']:.4f} (+/- {stats['accuracy_std']:.4f})"
        )
        return stats


def run_stability_test():
    # Load dataset
    dataset_path = os.path.join(
        os.path.dirname(__file__), "..", "datasets", "labeled_events_v2_enhanced.csv"
    )
    if not os.path.exists(dataset_path):
        print(f"❌ Dataset not found at {dataset_path}")
        return

    df = pd.read_csv(dataset_path)
    X = df.drop("label", axis=1)
    y = df["label"]

    # Normalize
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    validator = CrossValidator(n_splits=5)

    # 1. Evaluate Enhanced Model (V3)
    enhanced_model = RandomForestClassifier(
        n_estimators=100, max_depth=12, random_state=42
    )
    enhanced_stats = validator.evaluate_model(
        enhanced_model, X_scaled, y, "AttackClassifierV3_Enhanced"
    )

    # 2. Evaluate Baseline Model (Assume simpler params for baseline comparison)
    baseline_model = RandomForestClassifier(
        n_estimators=50, max_depth=5, random_state=42
    )
    baseline_stats = validator.evaluate_model(
        baseline_model, X_scaled, y, "AttackClassifier_Baseline"
    )

    # Save results for reporting
    results_dir = os.path.join(os.path.dirname(__file__), "..", "..", "reports")
    os.makedirs(results_dir, exist_ok=True)

    with open(os.path.join(results_dir, "stability_data.joblib"), "wb") as f:
        joblib.dump({"enhanced": enhanced_stats, "baseline": baseline_stats}, f)


if __name__ == "__main__":
    run_stability_test()
