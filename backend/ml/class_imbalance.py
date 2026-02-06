"""
Class Imbalance Analysis Module for PhantomNet ML Pipeline
Day 4 Deliverable - Model Quality Validation

This module provides functions to analyze class distribution,
compute per-class metrics, and assess imbalance impact.

Rules:
- Pure analysis
- Deterministic output
- No rebalancing or retraining
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, Optional
from sklearn.metrics import precision_score, recall_score, f1_score


def compute_class_distribution(
    y: np.ndarray,
    class_names: Optional[Dict[int, str]] = None
) -> Dict[str, Any]:
    """
    Compute class distribution statistics.
    
    Args:
        y: Label array
        class_names: Optional mapping of class indices to names
        
    Returns:
        Dictionary with count and ratio per class
    """
    if class_names is None:
        class_names = {0: "benign", 1: "attack"}
    
    y = np.array(y)
    unique, counts = np.unique(y, return_counts=True)
    total = len(y)
    
    distribution = {
        "total_samples": total,
        "classes": {}
    }
    
    for cls, count in zip(unique, counts):
        name = class_names.get(cls, f"class_{cls}")
        distribution["classes"][name] = {
            "class_id": int(cls),
            "count": int(count),
            "ratio": float(count / total) if total > 0 else 0.0,
            "percentage": float(count / total * 100) if total > 0 else 0.0
        }
    
    # Compute imbalance ratio (majority / minority)
    if len(counts) >= 2:
        majority = max(counts)
        minority = min(counts)
        distribution["imbalance_ratio"] = float(majority / minority) if minority > 0 else float('inf')
    else:
        distribution["imbalance_ratio"] = 1.0
    
    return distribution


def compute_per_class_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: Optional[Dict[int, str]] = None
) -> Dict[str, Dict[str, float]]:
    """
    Compute precision, recall, F1 for each class separately.
    
    Args:
        y_true: Ground truth labels
        y_pred: Predicted labels
        class_names: Optional mapping of class indices to names
        
    Returns:
        Dictionary with per-class metrics
    """
    if class_names is None:
        class_names = {0: "benign", 1: "attack"}
    
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    
    metrics = {}
    
    for cls_id, cls_name in class_names.items():
        # Binary metrics treating this class as positive
        y_true_binary = (y_true == cls_id).astype(int)
        y_pred_binary = (y_pred == cls_id).astype(int)
        
        metrics[cls_name] = {
            "precision": float(precision_score(y_true_binary, y_pred_binary, zero_division=0)),
            "recall": float(recall_score(y_true_binary, y_pred_binary, zero_division=0)),
            "f1": float(f1_score(y_true_binary, y_pred_binary, zero_division=0)),
            "support": int(np.sum(y_true == cls_id))
        }
    
    return metrics


def assess_imbalance_impact(
    distribution: Dict[str, Any],
    per_class_metrics: Dict[str, Dict[str, float]],
    accuracy: float
) -> Dict[str, Any]:
    """
    Assess whether class imbalance is materially affecting model behavior.
    
    Args:
        distribution: Output from compute_class_distribution()
        per_class_metrics: Output from compute_per_class_metrics()
        accuracy: Overall model accuracy
        
    Returns:
        Impact assessment dictionary with verdict
    """
    assessment = {
        "imbalance_ratio": distribution.get("imbalance_ratio", 1.0),
        "accuracy": accuracy,
        "issues": [],
        "verdict": ""
    }
    
    # Check if minority class has poor recall
    attack_metrics = per_class_metrics.get("attack", {})
    benign_metrics = per_class_metrics.get("benign", {})
    
    attack_recall = attack_metrics.get("recall", 0)
    benign_recall = benign_metrics.get("recall", 0)
    
    assessment["attack_recall"] = attack_recall
    assessment["benign_recall"] = benign_recall
    
    # Issue: High imbalance ratio
    if distribution["imbalance_ratio"] > 3.0:
        assessment["issues"].append(
            f"High imbalance ratio ({distribution['imbalance_ratio']:.2f}:1)"
        )
    
    # Issue: Accuracy inflated by majority class
    majority_ratio = max(
        [c["ratio"] for c in distribution["classes"].values()]
    )
    if accuracy < majority_ratio + 0.05:
        assessment["issues"].append(
            "Accuracy may be inflated by majority class (near baseline)"
        )
    
    # Issue: Poor minority recall
    if attack_recall < 0.7:
        assessment["issues"].append(
            f"Attack class recall is low ({attack_recall:.2%})"
        )
    
    # Issue: Large recall gap
    if abs(attack_recall - benign_recall) > 0.2:
        assessment["issues"].append(
            f"Large recall gap between classes ({abs(attack_recall - benign_recall):.2%})"
        )
    
    # Generate verdict
    if len(assessment["issues"]) == 0:
        assessment["verdict"] = "Class imbalance is NOT materially affecting model behavior."
        assessment["severity"] = "low"
    elif len(assessment["issues"]) <= 2 and attack_recall >= 0.7:
        assessment["verdict"] = "Class imbalance has MINOR impact on model behavior."
        assessment["severity"] = "medium"
    else:
        assessment["verdict"] = "Class imbalance IS materially affecting model behavior."
        assessment["severity"] = "high"
    
    return assessment


def analyze_split_distributions(
    y_full: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    class_names: Optional[Dict[int, str]] = None
) -> Dict[str, Dict[str, Any]]:
    """
    Compare class distributions across full, train, and test splits.
    
    Args:
        y_full: Full dataset labels
        y_train: Training set labels
        y_test: Test set labels
        class_names: Optional class name mapping
        
    Returns:
        Dictionary with distribution for each split
    """
    return {
        "full_dataset": compute_class_distribution(y_full, class_names),
        "train_split": compute_class_distribution(y_train, class_names),
        "test_split": compute_class_distribution(y_test, class_names)
    }


def generate_imbalance_report(
    distribution: Dict[str, Any],
    per_class_metrics: Dict[str, Dict[str, float]],
    assessment: Dict[str, Any]
) -> str:
    """
    Generate a human-readable imbalance analysis report.
    
    Returns:
        Formatted string report
    """
    lines = [
        "=" * 60,
        "CLASS IMBALANCE ANALYSIS REPORT",
        "=" * 60,
        "",
        "CLASS DISTRIBUTION:",
        "-" * 40
    ]
    
    for name, stats in distribution["classes"].items():
        lines.append(f"  {name.upper()}: {stats['count']} samples ({stats['percentage']:.1f}%)")
    
    lines.append(f"  Imbalance Ratio: {distribution['imbalance_ratio']:.2f}:1")
    lines.append("")
    lines.append("PER-CLASS METRICS:")
    lines.append("-" * 40)
    
    for name, metrics in per_class_metrics.items():
        lines.append(f"  {name.upper()}:")
        lines.append(f"    Precision: {metrics['precision']:.3f}")
        lines.append(f"    Recall: {metrics['recall']:.3f}")
        lines.append(f"    F1-Score: {metrics['f1']:.3f}")
        lines.append(f"    Support: {metrics['support']}")
    
    lines.append("")
    lines.append("IMPACT ASSESSMENT:")
    lines.append("-" * 40)
    lines.append(f"  Accuracy: {assessment['accuracy']:.3f}")
    lines.append(f"  Attack Recall: {assessment['attack_recall']:.3f}")
    lines.append(f"  Severity: {assessment['severity'].upper()}")
    
    if assessment["issues"]:
        lines.append("")
        lines.append("  Issues Identified:")
        for issue in assessment["issues"]:
            lines.append(f"    - {issue}")
    
    lines.append("")
    lines.append("VERDICT:")
    lines.append("-" * 40)
    lines.append(f"  {assessment['verdict']}")
    lines.append("=" * 60)
    
    return "\n".join(lines)
