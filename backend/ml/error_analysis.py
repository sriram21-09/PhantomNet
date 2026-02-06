"""
Error Analysis Module for PhantomNet ML Pipeline
Day 4 Deliverable - Model Quality Validation

This module provides functions to analyze misclassifications (FP/FN),
understand error patterns, and generate structured error breakdowns.

Rules:
- No plotting
- No MLflow logging
- No training
- Pure analysis only
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple


def compute_misclassification_indices(
    y_true: np.ndarray, 
    y_pred: np.ndarray
) -> Dict[str, np.ndarray]:
    """
    Identify indices of False Positives and False Negatives.
    
    Args:
        y_true: Ground truth labels (0 = benign, 1 = attack)
        y_pred: Predicted labels
        
    Returns:
        Dictionary with 'fp_indices' and 'fn_indices' arrays
    """
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    
    # False Positives: Predicted 1 (attack), Actual 0 (benign)
    fp_indices = np.where((y_pred == 1) & (y_true == 0))[0]
    
    # False Negatives: Predicted 0 (benign), Actual 1 (attack)
    fn_indices = np.where((y_pred == 0) & (y_true == 1))[0]
    
    return {
        "fp_indices": fp_indices,
        "fn_indices": fn_indices
    }


def analyze_error_distribution(
    X: pd.DataFrame,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray] = None
) -> Dict[str, Any]:
    """
    Analyze feature distributions and confidence scores for misclassified samples.
    
    Args:
        X: Feature matrix (DataFrame for feature names)
        y_true: Ground truth labels
        y_pred: Predicted labels
        y_proba: Optional probability scores (for class 1)
        
    Returns:
        Structured analysis dictionary
    """
    # Convert to numpy arrays and reset DataFrame index for consistent indexing
    y_true_arr = np.array(y_true).flatten()
    y_pred_arr = np.array(y_pred).flatten()
    X_reset = X.reset_index(drop=True)
    
    if y_proba is not None:
        y_proba = np.array(y_proba).flatten()
    
    indices = compute_misclassification_indices(y_true_arr, y_pred_arr)
    fp_indices = indices["fp_indices"]
    fn_indices = indices["fn_indices"]
    
    result = {
        "summary": {
            "total_samples": len(y_true_arr),
            "total_errors": len(fp_indices) + len(fn_indices),
            "false_positives": len(fp_indices),
            "false_negatives": len(fn_indices),
            "error_rate": (len(fp_indices) + len(fn_indices)) / len(y_true_arr) if len(y_true_arr) > 0 else 0
        },
        "false_positives": {},
        "false_negatives": {}
    }
    
    # Analyze False Positives
    if len(fp_indices) > 0:
        fp_features = X_reset.iloc[fp_indices]
        result["false_positives"]["count"] = len(fp_indices)
        result["false_positives"]["feature_stats"] = _compute_feature_stats(fp_features)
        
        if y_proba is not None:
            fp_proba = y_proba[fp_indices]
            result["false_positives"]["confidence_stats"] = _compute_confidence_stats(fp_proba)
    else:
        result["false_positives"]["count"] = 0
        result["false_positives"]["feature_stats"] = {}
        result["false_positives"]["confidence_stats"] = {}
    
    # Analyze False Negatives
    if len(fn_indices) > 0:
        fn_features = X_reset.iloc[fn_indices]
        result["false_negatives"]["count"] = len(fn_indices)
        result["false_negatives"]["feature_stats"] = _compute_feature_stats(fn_features)
        
        if y_proba is not None:
            fn_proba = y_proba[fn_indices]
            result["false_negatives"]["confidence_stats"] = _compute_confidence_stats(fn_proba)
    else:
        result["false_negatives"]["count"] = 0
        result["false_negatives"]["feature_stats"] = {}
        result["false_negatives"]["confidence_stats"] = {}
    
    return result


def _compute_feature_stats(df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    """Compute descriptive statistics for each feature."""
    stats = {}
    for col in df.columns:
        stats[col] = {
            "mean": float(df[col].mean()),
            "std": float(df[col].std()) if len(df) > 1 else 0.0,
            "min": float(df[col].min()),
            "max": float(df[col].max()),
            "median": float(df[col].median())
        }
    return stats


def _compute_confidence_stats(proba: np.ndarray) -> Dict[str, float]:
    """Compute statistics for prediction confidence scores."""
    return {
        "mean_confidence": float(np.mean(proba)),
        "std_confidence": float(np.std(proba)) if len(proba) > 1 else 0.0,
        "min_confidence": float(np.min(proba)),
        "max_confidence": float(np.max(proba)),
        "low_confidence_count": int(np.sum(proba < 0.6)),
        "high_confidence_count": int(np.sum(proba >= 0.8))
    }


def get_error_samples(
    X: pd.DataFrame,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    error_type: str = "all",
    max_samples: int = 10
) -> pd.DataFrame:
    """
    Retrieve sample records of misclassified instances.
    
    Args:
        X: Feature matrix
        y_true: Ground truth labels
        y_pred: Predicted labels
        error_type: "fp", "fn", or "all"
        max_samples: Maximum number of samples to return
        
    Returns:
        DataFrame with error samples and their details
    """
    # Convert to numpy arrays and reset DataFrame index for consistent indexing
    y_true_arr = np.array(y_true).flatten()
    y_pred_arr = np.array(y_pred).flatten()
    X_reset = X.reset_index(drop=True)
    
    indices = compute_misclassification_indices(y_true_arr, y_pred_arr)
    
    if error_type == "fp":
        error_indices = indices["fp_indices"]
    elif error_type == "fn":
        error_indices = indices["fn_indices"]
    else:
        error_indices = np.concatenate([indices["fp_indices"], indices["fn_indices"]])
    
    if len(error_indices) == 0:
        return pd.DataFrame()
    
    # Limit samples
    sample_indices = error_indices[:max_samples]
    
    result = X_reset.iloc[sample_indices].copy()
    result["actual"] = y_true_arr[sample_indices]
    result["predicted"] = y_pred_arr[sample_indices]
    result["error_type"] = ["FP" if y_true_arr[i] == 0 else "FN" for i in sample_indices]
    
    return result


def generate_error_summary(analysis: Dict[str, Any]) -> str:
    """
    Generate a human-readable summary of the error analysis.
    
    Args:
        analysis: Output from analyze_error_distribution()
        
    Returns:
        Formatted string summary
    """
    summary = analysis["summary"]
    fp = analysis["false_positives"]
    fn = analysis["false_negatives"]
    
    lines = [
        "=" * 60,
        "ERROR ANALYSIS SUMMARY",
        "=" * 60,
        f"Total Samples: {summary['total_samples']}",
        f"Total Errors: {summary['total_errors']} ({summary['error_rate']:.2%})",
        f"False Positives (Benign → Attack): {summary['false_positives']}",
        f"False Negatives (Attack → Benign): {summary['false_negatives']}",
        "-" * 60,
    ]
    
    if fp.get("confidence_stats"):
        cs = fp["confidence_stats"]
        lines.append("False Positive Confidence:")
        lines.append(f"  Mean: {cs['mean_confidence']:.3f}, Low-conf: {cs['low_confidence_count']}, High-conf: {cs['high_confidence_count']}")
    
    if fn.get("confidence_stats"):
        cs = fn["confidence_stats"]
        lines.append("False Negative Confidence:")
        lines.append(f"  Mean: {cs['mean_confidence']:.3f}, Low-conf: {cs['low_confidence_count']}, High-conf: {cs['high_confidence_count']}")
    
    lines.append("=" * 60)
    
    return "\n".join(lines)
