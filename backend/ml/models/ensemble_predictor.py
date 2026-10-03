"""
PhantomNet Canonical Hybrid Threat-Scoring Ensemble Predictor (Phase ML-2)
========================================================================
Authoritative implementation of the calibrated hybrid ensemble architecture:
    Hybrid Threat Score = 0.85 * RF Score + 0.15 * Calibrated IF Score

Enforces:
- Canonical 12D FeatureExtractor contract validation
- Strict rejection of incompatible checkpoints (6D, 13D, 15D, 32D) without slicing hacks
- Robust Min-Max inversion calibration of Isolation Forest decision_function
- Directional alignment (higher score = higher threat/anomaly evidence)
- Single source of truth for severity (CRITICAL, HIGH, MEDIUM, LOW) and decisions (BLOCK, ALERT, ALLOW)
"""

import os
import joblib
import pandas as pd
import numpy as np
import logging
from typing import Dict, Any, Optional, Tuple, Union

try:
    from ml.config.thresholds import (
        RF_WEIGHT,
        IF_WEIGHT,
        CRITICAL_THRESHOLD,
        HIGH_THRESHOLD,
        MEDIUM_THRESHOLD,
        BLOCK_THRESHOLD,
        ALERT_THRESHOLD,
        IF_CALIBRATION_MIN,
        IF_CALIBRATION_MAX,
    )
    from ml.config.feature_schema import (
        CANONICAL_FEATURE_NAMES,
        CANONICAL_FEATURE_COUNT,
        SCHEMA_VERSION,
        validate_feature_vector,
        KNOWN_INCOMPATIBLE_DIMENSIONS,
    )
    from ml.feature_extractor import FeatureExtractor
except ImportError:
    from backend.ml.config.thresholds import (
        RF_WEIGHT,
        IF_WEIGHT,
        CRITICAL_THRESHOLD,
        HIGH_THRESHOLD,
        MEDIUM_THRESHOLD,
        BLOCK_THRESHOLD,
        ALERT_THRESHOLD,
        IF_CALIBRATION_MIN,
        IF_CALIBRATION_MAX,
    )
    from backend.ml.config.feature_schema import (
        CANONICAL_FEATURE_NAMES,
        CANONICAL_FEATURE_COUNT,
        SCHEMA_VERSION,
        validate_feature_vector,
        KNOWN_INCOMPATIBLE_DIMENSIONS,
    )
    from backend.ml.feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def validate_model_compatibility(model: Any, model_name: str = "Model") -> None:
    """
    Validates model feature compatibility against the canonical 12D schema (Phase ML-3).
    Rejects incompatible checkpoints (e.g. 6D, 13D, 15D, 32D) explicitly.
    Positional slicing hacks (e.g. iloc[:, :12] or [:, :12]) are strictly forbidden.

    Raises:
        ValueError: Containing model identifier, detected dimension, expected dimension,
                    compatibility status, and recommended disposition.
    """
    if model is None:
        return

    expected_count = CANONICAL_FEATURE_COUNT

    # 1. Inspect Pipeline steps if applicable
    n_features = getattr(model, "n_features_in_", None)
    feat_names = getattr(model, "feature_names_in_", None)

    if hasattr(model, "named_steps"):
        for step_name, step_obj in model.named_steps.items():
            step_dim = getattr(step_obj, "n_features_in_", None)
            step_names = getattr(step_obj, "feature_names_in_", None)
            if step_dim is not None:
                n_features = step_dim
            if step_names is not None:
                feat_names = step_names

    # 2. Check feature count
    if n_features is not None and n_features != expected_count:
        status = "QUARANTINED_INCOMPATIBLE"
        disposition = (
            f"Quarantine checkpoint '{model_name}'; strictly forbidden from production "
            f"inference under Phase ML-3 contract."
        )
        raise ValueError(
            f"Model Compatibility Violation [{status}]:\n"
            f"  • Model Identifier:       {model_name}\n"
            f"  • Detected Dimension:     {n_features} features\n"
            f"  • Expected Dimension:     {expected_count} features ({list(CANONICAL_FEATURE_NAMES)})\n"
            f"  • Known Incompatible Dims:{KNOWN_INCOMPATIBLE_DIMENSIONS}\n"
            f"  • Compatibility Status:   {status}\n"
            f"  • Recommended Action:     {disposition}"
        )

    # 3. Check feature names and sequence if available
    if feat_names is not None:
        names_list = list(feat_names)
        if tuple(names_list) != CANONICAL_FEATURE_NAMES:
            status = "INCOMPATIBLE_SCHEMA_MISMATCH"
            disposition = (
                f"Quarantine checkpoint '{model_name}'; feature names/ordering conflict with "
                f"authoritative {SCHEMA_VERSION} contract."
            )
            raise ValueError(
                f"Model Schema Mismatch [{status}]:\n"
                f"  • Model Identifier:       {model_name}\n"
                f"  • Detected Features:      {names_list}\n"
                f"  • Expected Features:      {list(CANONICAL_FEATURE_NAMES)}\n"
                f"  • Compatibility Status:   {status}\n"
                f"  • Recommended Action:     {disposition}"
            )


class EnsemblePredictor:
    """
    Canonical Hybrid Ensemble Predictor combining Random Forest classifier
    and calibrated Isolation Forest anomaly detector.
    Single source of truth for the 0.85 RF + 0.15 IF formulation.
    """

    def __init__(
        self,
        rf_model: Any = None,
        if_model: Any = None,
        rf_path: Optional[str] = None,
        if_path: Optional[str] = None,
        w_rf: float = RF_WEIGHT,
        w_if: float = IF_WEIGHT,
        s_min: float = IF_CALIBRATION_MIN,
        s_max: float = IF_CALIBRATION_MAX,
    ):
        # Validate weights
        if not np.isclose(w_rf + w_if, 1.0, atol=1e-4):
            raise ValueError(f"Ensemble weights must sum to 1.0 (got w_rf={w_rf}, w_if={w_if})")

        # Explicit rejection of obsolete 0.70 / 0.30 weights if passed
        if np.isclose(w_rf, 0.70, atol=1e-4) and np.isclose(w_if, 0.30, atol=1e-4):
            logger.warning(
                "Obsolete ensemble weights (0.70/0.30) detected. "
                "Enforcing canonical experimental formulation (0.85 RF / 0.15 IF) per Phase ML-2 Rule 3."
            )
            w_rf = RF_WEIGHT
            w_if = IF_WEIGHT

        self.w_rf = float(w_rf)
        self.w_if = float(w_if)
        self.s_min = float(s_min)
        self.s_max = float(s_max)

        # Paths
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        registry_dir = os.path.join(base_dir, "ml_models", "registry")
        models_dir = os.path.join(base_dir, "ml_models")

        canonical_rf_path = os.path.join(registry_dir, "AttackClassifier_Enhanced_v1.0.0.pkl")
        if not os.path.exists(canonical_rf_path):
            canonical_rf_path = os.path.join(models_dir, "attack_classifier_latest.pkl")

        canonical_if_path = os.path.join(models_dir, "iforest_baseline.pkl")

        self.rf_path = rf_path or canonical_rf_path
        self.if_path = if_path or canonical_if_path

        self.rf_model = rf_model
        self.if_model = if_model

        # Only auto-load defaults if neither model was passed, or if specific paths were provided
        auto_load_defaults = (rf_model is None and if_model is None)
        if self.rf_model is None and (rf_path is not None or auto_load_defaults):
            self._load_rf()
        if self.if_model is None and (if_path is not None or auto_load_defaults):
            self._load_if()

        # Validate compatibility of loaded models
        validate_model_compatibility(self.rf_model, "Random Forest")
        validate_model_compatibility(self.if_model, "Isolation Forest")

    def _load_rf(self) -> None:
        """Loads Random Forest model from path."""
        if self.rf_path and os.path.exists(self.rf_path):
            try:
                loaded = joblib.load(self.rf_path)
                validate_model_compatibility(loaded, "Random Forest")
                self.rf_model = loaded
                logger.info(f"EnsemblePredictor: Loaded RF model from {self.rf_path}")
            except Exception as e:
                logger.warning(f"EnsemblePredictor: Failed to load RF from {self.rf_path}: {e}")

    def _load_if(self) -> None:
        """Loads Isolation Forest model from path."""
        if self.if_path and os.path.exists(self.if_path):
            try:
                loaded_if = joblib.load(self.if_path)
                validate_model_compatibility(loaded_if, "Isolation Forest")
                self.if_model = loaded_if
                logger.info(f"EnsemblePredictor: Loaded IF model from {self.if_path}")
            except Exception as e:
                logger.warning(f"EnsemblePredictor: Failed to load IF from {self.if_path}: {e}")

    # ========================================================================
    # CALIBRATION LOGIC (Rule 6 & Rule 7)
    # ========================================================================

    def calibrate_if_score(self, raw_score: Union[float, np.ndarray]) -> Union[float, np.ndarray]:
        """
        Calibrates raw Isolation Forest decision_function output to [0.0, 1.0].
        Raw decision_function:
            Negative values (< 0) denote anomalies (outliers).
            Positive values (> 0) denote normal inliers.
        Min-Max Robust Inversion:
            S_IF = 1.0 - (s - s_min) / (s_max - s_min + 1e-9)
        Semantics:
            0.0 -> completely normal (low threat evidence)
            1.0 -> highly anomalous (high threat evidence)
        Directionally aligned with Random Forest malicious probability P_RF.
        """
        denom = (self.s_max - self.s_min) + 1e-9
        normalized = 1.0 - ((raw_score - self.s_min) / denom)
        return np.clip(normalized, 0.0, 1.0)

    # ========================================================================
    # SEVERITY & DECISION MAPPING (Rule 8)
    # ========================================================================

    @staticmethod
    def classify_severity(score: float, context: Any = None) -> str:
        """
        Maps a canonical threat score (0.0 - 1.0) to authoritative severity.
        Base thresholds:
            CRITICAL >= 0.80
            HIGH     >= 0.60
            MEDIUM   >= 0.40
            LOW      <  0.40
        """
        if context and getattr(context, "is_malicious", False):
            return "CRITICAL"

        low_max = MEDIUM_THRESHOLD   # 0.40
        med_max = HIGH_THRESHOLD     # 0.60
        high_max = CRITICAL_THRESHOLD # 0.80

        if context:
            ts = getattr(context, "timestamp", None)
            if ts:
                try:
                    from dateutil import parser
                    dt = parser.parse(str(ts))
                    if 0 <= dt.hour <= 5:
                        med_max -= 0.10
                        high_max -= 0.10
                except Exception:
                    pass

            h_type = getattr(context, "honeypot_type", None)
            if h_type and str(h_type).upper() in ["SSH", "TELNET", "RDP"]:
                low_max -= 0.15
                med_max -= 0.15
                high_max -= 0.15

            att = getattr(context, "attack_type", None)
            if att and str(att).upper() in ["SSH_BRUTE_FORCE", "SQL_INJECTION", "EXPLOIT_PAYLOAD"]:
                low_max = min(low_max, 0.25)
                med_max = min(med_max, 0.50)

        low_max = max(0.15, low_max)
        med_max = max(0.30, med_max)
        high_max = max(0.50, high_max)

        if score >= high_max:
            return "CRITICAL"
        elif score >= med_max:
            return "HIGH"
        elif score >= low_max:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def classify_decision(score: float, context: Any = None) -> str:
        """
        Maps a canonical threat score (0.0 - 1.0) to authoritative enforcement action:
            BLOCK: score >= 0.80 or explicit malicious ground truth
            ALERT: score >= 0.50 or recognized high-danger attack signature
            ALLOW: score <  0.50
        """
        if score >= BLOCK_THRESHOLD or (context and getattr(context, "is_malicious", False)):
            return "BLOCK"
        elif score >= ALERT_THRESHOLD:
            return "ALERT"
        elif context and getattr(context, "attack_type", None) in [
            "SQL_INJECTION", "EXPLOIT_PAYLOAD", "SSH_BRUTE_FORCE"
        ]:
            return "ALERT"
        else:
            return "ALLOW"

    # ========================================================================
    # CANONICAL SCORING METHODS
    # ========================================================================

    def score_vector(self, X_df: Any) -> Dict[str, Any]:
        """
        Evaluates a single event represented as a 1-row DataFrame or vector.
        Validates schema, runs RF + IF, applies calibration, blends with 0.85/0.15.
        Returns structured scoring dictionary.
        """
        arr_2d = validate_feature_vector(X_df)
        if not isinstance(X_df, pd.DataFrame):
            X_df = pd.DataFrame(arr_2d, columns=list(CANONICAL_FEATURE_NAMES))
        else:
            X_df = X_df[list(CANONICAL_FEATURE_NAMES)]

        # 1. Supervised Random Forest Probability
        rf_prob = 0.0
        confidence = 0.5
        if self.rf_model is not None:
            if hasattr(self.rf_model, "predict_proba"):
                probs = self.rf_model.predict_proba(X_df)
                rf_prob = float(probs[0][1]) if probs.shape[1] > 1 else float(probs[0][0])
                confidence = float(np.max(probs[0]))
            elif hasattr(self.rf_model, "predict"):
                pred = self.rf_model.predict(X_df)[0]
                rf_prob = 1.0 if pred == 1 else 0.0
                confidence = 0.80

        # 2. Unsupervised Isolation Forest Anomaly Score
        raw_if_score = 0.0
        calibrated_if_score = 0.0
        if self.if_model is not None:
            if hasattr(self.if_model, "decision_function"):
                raw_if = self.if_model.decision_function(X_df)[0]
                raw_if_score = float(raw_if)
                calibrated_if_score = float(self.calibrate_if_score(raw_if))
            elif hasattr(self.if_model, "score_samples"):
                score_samp = self.if_model.score_samples(X_df)[0]
                raw_if_score = float(score_samp)
                calibrated_if_score = float(self.calibrate_if_score(score_samp))
            elif hasattr(self.if_model, "predict"):
                p = self.if_model.predict(X_df)[0]
                raw_if_score = -0.10 if p == -1 else 0.10
                calibrated_if_score = 0.85 if p == -1 else 0.10

        # 3. Canonical Hybrid Blending: 0.85 RF + 0.15 IF
        if self.rf_model is not None and self.if_model is not None:
            final_score = (self.w_rf * rf_prob) + (self.w_if * calibrated_if_score)
        elif self.rf_model is not None:
            final_score = rf_prob
        elif self.if_model is not None:
            final_score = calibrated_if_score
        else:
            final_score = 0.0

        final_score = float(np.clip(final_score, 0.0, 1.0))

        return {
            "final_score": final_score,
            "rf_score": float(np.clip(rf_prob, 0.0, 1.0)),
            "raw_if_score": raw_if_score,
            "calibrated_if_score": float(np.clip(calibrated_if_score, 0.0, 1.0)),
            "confidence": confidence,
            "model_version": "v1.0.0-canonical-12d",
        }

    # ========================================================================
    # BACKWARD-COMPATIBLE PUBLIC INTERFACES
    # ========================================================================

    def predict(self, rf_features: Any, if_features: Any = None) -> Dict[str, Any]:
        """
        Backward-compatible predict interface for single event evaluation.
        """
        arr_2d = validate_feature_vector(rf_features)
        if not isinstance(rf_features, pd.DataFrame):
            rf_features = pd.DataFrame(arr_2d, columns=list(CANONICAL_FEATURE_NAMES))
        else:
            rf_features = rf_features[list(CANONICAL_FEATURE_NAMES)]

        scored = self.score_vector(rf_features)
        prediction = 1 if scored["final_score"] >= 0.50 else 0

        return {
            "prediction": prediction,
            "ensemble_score": scored["final_score"],
            "rf_prob": scored["rf_score"],
            "if_score": scored["calibrated_if_score"],
            "raw_if_score": scored["raw_if_score"],
            "threat_level": self.classify_severity(scored["final_score"]),
            "decision": self.classify_decision(scored["final_score"]),
        }

    def predict_batch(
        self, rf_features_df: Any, if_features_df: Optional[Any] = None
    ) -> pd.DataFrame:
        """
        Vectorized batch prediction across a DataFrame or matrix of events.
        Strictly enforces 12D canonical schema.
        """
        arr_2d = validate_feature_vector(rf_features_df)
        if not isinstance(rf_features_df, pd.DataFrame):
            rf_features_df = pd.DataFrame(arr_2d, columns=list(CANONICAL_FEATURE_NAMES))
        else:
            rf_features_df = rf_features_df[list(CANONICAL_FEATURE_NAMES)]

        n_samples = len(rf_features_df)
        rf_probs = np.zeros(n_samples)
        raw_if_scores = np.zeros(n_samples)
        calibrated_if_scores = np.zeros(n_samples)

        # 1. RF Supervised Probabilities
        if self.rf_model is not None:
            if hasattr(self.rf_model, "predict_proba"):
                probs = self.rf_model.predict_proba(rf_features_df)
                rf_probs = probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]
            elif hasattr(self.rf_model, "predict"):
                rf_probs = self.rf_model.predict(rf_features_df).astype(float)

        # 2. IF Anomaly Scores
        if_input = if_features_df if if_features_df is not None else rf_features_df
        if not isinstance(if_input, pd.DataFrame):
            cols = FeatureExtractor.FEATURE_NAMES if (
                hasattr(if_input, "shape") and if_input.shape[1] == len(FeatureExtractor.FEATURE_NAMES)
            ) else None
            if_input = pd.DataFrame(if_input, columns=cols)

        if self.if_model is not None:
            if hasattr(self.if_model, "decision_function"):
                raw_if_scores = self.if_model.decision_function(if_input)
                calibrated_if_scores = self.calibrate_if_score(raw_if_scores)
            elif hasattr(self.if_model, "score_samples"):
                score_samples = self.if_model.score_samples(if_input)
                raw_if_scores = score_samples
                calibrated_if_scores = self.calibrate_if_score(score_samples)
            elif hasattr(self.if_model, "predict"):
                preds = self.if_model.predict(if_input)
                raw_if_scores = np.where(preds == -1, -0.10, 0.10)
                calibrated_if_scores = np.where(preds == -1, 0.85, 0.10)

        # 3. Canonical Ensemble Blending (0.85 RF + 0.15 IF)
        if self.rf_model is not None and self.if_model is not None:
            ensemble_scores = (self.w_rf * rf_probs) + (self.w_if * calibrated_if_scores)
        elif self.rf_model is not None:
            ensemble_scores = rf_probs
        elif self.if_model is not None:
            ensemble_scores = calibrated_if_scores
        else:
            ensemble_scores = np.zeros(n_samples)

        ensemble_scores = np.clip(ensemble_scores, 0.0, 1.0)
        predictions = (ensemble_scores >= 0.50).astype(int)

        return pd.DataFrame({
            "ensemble_score": ensemble_scores,
            "ensemble_prediction": predictions,
            "rf_prob": rf_probs,
            "if_score": calibrated_if_scores,
            "raw_if_score": raw_if_scores,
        })

    def predict_proba(self, X: Any) -> np.ndarray:
        """
        Drop-in support for Scikit-Learn API expectations (returns [1 - p, p]).
        Enables seamless replacement wherever a standard Scikit-Learn classifier is expected.
        Strictly enforces 12D schema.
        """
        arr_2d = validate_feature_vector(X)
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(arr_2d, columns=list(CANONICAL_FEATURE_NAMES))
        else:
            X = X[list(CANONICAL_FEATURE_NAMES)]

        res_df = self.predict_batch(X)
        probs = res_df["ensemble_score"].values
        return np.vstack((1.0 - probs, probs)).T
