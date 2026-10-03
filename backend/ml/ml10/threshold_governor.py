"""
PhantomNet Phase ML-10: Decision Threshold Governance Framework
===============================================================
Enforces strict development-isolated threshold optimization, sensitivity testing (±0.01, ±0.02, ±0.05),
and explicit tracking of threshold provenance.
"""

from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix


class PolicyObjective(str, Enum):
    F1_OPTIMAL = "F1_OPTIMAL"
    YOUDEN_J = "YOUDEN_J"
    RECALL_CONSTRAINED_95 = "RECALL_CONSTRAINED_95"
    FPR_CONSTRAINED_01 = "FPR_CONSTRAINED_01"
    CALIBRATED_PROBABILITY_50 = "CALIBRATED_PROBABILITY_50"
    HISTORICAL_ALERT_50 = "HISTORICAL_ALERT_50"
    HISTORICAL_BLOCK_80 = "HISTORICAL_BLOCK_80"


class ThresholdGovernor:
    """
    Optimizes and validates threshold policies strictly on development data.
    """

    def __init__(self, dev_scores: np.ndarray, dev_labels: np.ndarray):
        self.dev_scores = np.asarray(dev_scores, dtype=np.float64)
        self.dev_labels = np.asarray(dev_labels, dtype=np.int64)
        self.grid = np.linspace(0.0, 1.0, 101)

    def optimize_policy(self, objective: PolicyObjective) -> Dict[str, Any]:
        """
        Selects optimal threshold on development data according to the objective.
        """
        if objective == PolicyObjective.HISTORICAL_ALERT_50:
            return self._evaluate_threshold(0.50, objective.value, provenance="HISTORICAL_HEURISTIC_NO_PRESERVED_PROVENANCE")
        if objective == PolicyObjective.HISTORICAL_BLOCK_80:
            return self._evaluate_threshold(0.80, objective.value, provenance="HISTORICAL_HEURISTIC_NO_PRESERVED_PROVENANCE")
        if objective == PolicyObjective.CALIBRATED_PROBABILITY_50:
            return self._evaluate_threshold(0.50, objective.value, provenance="THEORETICAL_BAYES_RISK_NEUTRAL")

        best_thresh = 0.50
        best_metric = -1.0

        for t in self.grid:
            preds = (self.dev_scores >= t).astype(int)
            tn, fp, fn, tp = confusion_matrix(self.dev_labels, preds, labels=[0, 1]).ravel()
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
            youden = recall - fpr

            if objective == PolicyObjective.F1_OPTIMAL:
                if f1 > best_metric:
                    best_metric = f1
                    best_thresh = t

            elif objective == PolicyObjective.YOUDEN_J:
                if youden > best_metric:
                    best_metric = youden
                    best_thresh = t

            elif objective == PolicyObjective.RECALL_CONSTRAINED_95:
                if recall >= 0.95:
                    if precision > best_metric:
                        best_metric = precision
                        best_thresh = t

            elif objective == PolicyObjective.FPR_CONSTRAINED_01:
                if fpr <= 0.01:
                    if recall > best_metric:
                        best_metric = recall
                        best_thresh = t

        return self._evaluate_threshold(best_thresh, objective.value, provenance="DEVELOPMENT_SET_OPTIMIZED")

    def evaluate_sensitivity(self, base_threshold: float, perturbations: List[float] = [-0.05, -0.02, -0.01, 0.0, 0.01, 0.02, 0.05]) -> List[Dict[str, Any]]:
        """
        Measures metric volatility across small perturbations around a candidate threshold.
        """
        results = []
        for delta in perturbations:
            t = float(np.clip(base_threshold + delta, 0.0, 1.0))
            perf = self._evaluate_threshold(t, f"PERTURBATION_{delta:+.2f}", provenance="SENSITIVITY_SWEEP")
            perf["delta"] = float(delta)
            perf["perturbed_threshold"] = t
            results.append(perf)
        return results

    def _evaluate_threshold(self, threshold: float, objective_name: str, provenance: str) -> Dict[str, Any]:
        preds = (self.dev_scores >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(self.dev_labels, preds, labels=[0, 1]).ravel()
        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        balanced_acc = float(0.5 * (tp / (tp + fn) + tn / (tn + fp)))

        return {
            "objective": objective_name,
            "threshold": float(threshold),
            "provenance": provenance,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fpr": fpr,
            "fnr": fnr,
            "balanced_accuracy": balanced_acc,
            "confusion_matrix": {
                "tp": int(tp),
                "fp": int(fp),
                "tn": int(tn),
                "fn": int(fn)
            }
        }
