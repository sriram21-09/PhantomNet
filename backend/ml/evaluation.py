# backend/ml/evaluation.py

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)


def evaluate_classification(y_true, y_pred, average="weighted"):
    """
    Evaluate classification performance.

    Parameters:
    - y_true: ground truth labels
    - y_pred: predicted labels
    - average: averaging method for multiclass metrics

    Returns:
    - dict containing accuracy, precision, recall, f1
    """

    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, average=average, zero_division=0),
        "recall": recall_score(y_true, y_pred, average=average, zero_division=0),
        "f1": f1_score(y_true, y_pred, average=average, zero_division=0),
    }

    return metrics


def get_classification_report(y_true, y_pred):
    """
    Generate detailed classification report.
    Useful for debugging and analysis.
    """
    return classification_report(y_true, y_pred, zero_division=0)
