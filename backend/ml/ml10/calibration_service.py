"""
PhantomNet Phase ML-10: Probability Calibration Service
=======================================================
Implements development-isolated post-hoc probability calibration (Platt Sigmoid and Isotonic Regression).
Strictly separates ordinal threat scoring from calibrated posterior probability estimation.
"""

from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.isotonic import IsotonicRegression


class CalibrationMethod(str, Enum):
    UNSET = "UNSET"
    PLATT = "PLATT"
    ISOTONIC = "ISOTONIC"


class CalibrationService:
    """
    Fits and evaluates post-hoc calibration mapping raw model scores to empirical posterior probabilities.
    """

    def __init__(self, method: CalibrationMethod = CalibrationMethod.PLATT):
        self.method = method
        self.platt_model: Optional[LogisticRegression] = None
        self.isotonic_model: Optional[IsotonicRegression] = None
        self.is_fitted: bool = False
        self.dev_ece: Optional[float] = None
        self.dev_brier: Optional[float] = None

    def fit_on_development(self, dev_scores: np.ndarray, dev_labels: np.ndarray) -> Dict[str, Any]:
        """
        Fits calibration model strictly on development data. Never touches test data.
        """
        scores = np.asarray(dev_scores, dtype=np.float64).flatten()
        labels = np.asarray(dev_labels, dtype=np.int64).flatten()

        if self.method == CalibrationMethod.PLATT:
            # Platt scaling: LogisticRegression on 1D logit / raw score
            lr = LogisticRegression(C=1.0, solver="lbfgs", random_state=42)
            lr.fit(scores.reshape(-1, 1), labels)
            self.platt_model = lr
            self.is_fitted = True
            cal_probs = lr.predict_proba(scores.reshape(-1, 1))[:, 1]

        elif self.method == CalibrationMethod.ISOTONIC:
            iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
            iso.fit(scores, labels)
            self.isotonic_model = iso
            self.is_fitted = True
            cal_probs = iso.predict(scores)

        else:
            raise ValueError(f"Unsupported calibration method: {self.method}")

        self.dev_ece = self.compute_ece(labels, cal_probs)
        self.dev_brier = float(np.mean((cal_probs - labels) ** 2))

        return {
            "method": self.method.value,
            "is_fitted": self.is_fitted,
            "sample_size": len(labels),
            "dev_ece": float(self.dev_ece),
            "dev_brier": float(self.dev_brier)
        }

    def predict_probability(self, raw_score: float) -> float:
        """
        Transforms a raw score into a calibrated probability.
        """
        if not self.is_fitted:
            raise RuntimeError("CalibrationService must be fitted on development data before predicting probabilities.")

        val = np.array([raw_score], dtype=np.float64)
        if self.method == CalibrationMethod.PLATT:
            prob = self.platt_model.predict_proba(val.reshape(-1, 1))[0, 1]
        elif self.method == CalibrationMethod.ISOTONIC:
            prob = self.isotonic_model.predict(val)[0]
        else:
            prob = raw_score

        return float(np.clip(prob, 0.0, 1.0))

    def predict_probabilities_batch(self, raw_scores: np.ndarray) -> np.ndarray:
        """
        Transforms batch of raw scores into calibrated probabilities.
        """
        if not self.is_fitted:
            raise RuntimeError("CalibrationService must be fitted on development data before predicting probabilities.")

        scores = np.asarray(raw_scores, dtype=np.float64).flatten()
        if self.method == CalibrationMethod.PLATT:
            probs = self.platt_model.predict_proba(scores.reshape(-1, 1))[:, 1]
        elif self.method == CalibrationMethod.ISOTONIC:
            probs = self.isotonic_model.predict(scores)
        else:
            probs = scores

        return np.clip(probs, 0.0, 1.0)

    @staticmethod
    def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, num_bins: int = 10) -> float:
        """
        Computes Expected Calibration Error (ECE) with equal-width binning.
        """
        y_true = np.asarray(y_true, dtype=np.int64)
        y_prob = np.asarray(y_prob, dtype=np.float64)

        bin_boundaries = np.linspace(0, 1, num_bins + 1)
        ece = 0.0
        n_samples = len(y_true)

        for b in range(num_bins):
            bin_lower = bin_boundaries[b]
            bin_upper = bin_boundaries[b + 1]

            if b == num_bins - 1:
                mask = (y_prob >= bin_lower) & (y_prob <= bin_upper)
            else:
                mask = (y_prob >= bin_lower) & (y_prob < bin_upper)

            bin_count = np.sum(mask)
            if bin_count > 0:
                bin_acc = np.mean(y_true[mask])
                bin_conf = np.mean(y_prob[mask])
                ece += (bin_count / n_samples) * abs(bin_acc - bin_conf)

        return float(ece)

    @staticmethod
    def compute_brier_score(y_true: np.ndarray, y_prob: np.ndarray) -> float:
        """
        Computes Mean Squared Brier Score.
        """
        y_true = np.asarray(y_true, dtype=np.float64)
        y_prob = np.asarray(y_prob, dtype=np.float64)
        return float(np.mean((y_prob - y_true) ** 2))
