"""
Model Comparison: Gradient Boosting vs Random Forest
---------------------------------------------------
SOC-first evaluation:
- Recall (PRIMARY)
- F1-score
- Precision
- Accuracy (secondary)
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from sklearn.ensemble import RandomForestClassifier

from backend.models.gradient_boosting import build_gradient_boosting_model
from backend.ml.feature_extractor import FeatureExtractor


def load_dataset(path: str):
    """
    Load dataset and enforce feature + label contract.
    """
    df = pd.read_csv(path)

    feature_columns = FeatureExtractor.FEATURE_NAMES
    X = df[feature_columns]
    y = df["label"].astype(int)   # IMPORTANT FIX

    return X, y


def evaluate_model(name, model, X_test, y_test):
    preds = model.predict(X_test)

    print(f"\n=== {name} ===")
    print(f"Accuracy : {accuracy_score(y_test, preds):.3f}")
    print(f"Precision: {precision_score(y_test, preds):.3f}")
    print(f"Recall   : {recall_score(y_test, preds):.3f}")
    print(f"F1-score : {f1_score(y_test, preds):.3f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))


def main():
    X, y = load_dataset("data/training_dataset.csv")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        stratify=y,
        random_state=42
    )

    # SAFETY CHECK (MANDATORY)
    print("\nTrain label distribution:")
    print(y_train.value_counts())

    print("\nTest label distribution:")
    print(y_test.value_counts())

    # -------------------------
    # Gradient Boosting
    # -------------------------
    gb_model = build_gradient_boosting_model()
    gb_model.fit(X_train, y_train)
    evaluate_model("Gradient Boosting", gb_model, X_test, y_test)

    # -------------------------
    # Random Forest
    # -------------------------
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        class_weight="balanced",
        random_state=42
    )
    rf_model.fit(X_train, y_train)
    evaluate_model("Random Forest", rf_model, X_test, y_test)


if __name__ == "__main__":
    main()
