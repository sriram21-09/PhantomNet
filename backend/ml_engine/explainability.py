"""
SHAP-based explainability service for ML model predictions.
Provides insights into feature importance for specific threat detections.
"""
import os
import logging
from typing import Dict, Any, List, Optional, Union

try:
    import shap
except Exception as e:
    shap = None
import pandas as pd
import numpy as np

from ml.feature_extractor import FeatureExtractor
from ml.model_loader import load_model

logger = logging.getLogger("explainability")


class ModelExplainer:
    """
    Handles generation of SHAP explanations for Random Forest predictions.
    Lazy-loads the model and explainer upon first use.
    """
    def __init__(self) -> None:
        """
        Initializes the ModelExplainer with default values for model and explainer.
        """
        self.rf_model = None
        self.scaler = None
        self.explainer = None
        self.feature_names = FeatureExtractor.FEATURE_NAMES
        self.feature_extractor = FeatureExtractor()

    def _initialize(self) -> None:
        """Lazy load the Random Forest model and TreeExplainer."""
        if not self.rf_model:
            model_obj = load_model()
            if model_obj is not None:
                # Handle sklearn Pipeline, dictionary wrapper, or bare model
                if hasattr(model_obj, "named_steps"):
                    self.scaler = model_obj.named_steps.get("scaler")
                    self.rf_model = model_obj.named_steps.get("rf") or model_obj.named_steps.get("classifier")
                elif isinstance(model_obj, dict):
                    self.rf_model = model_obj.get("model") or model_obj.get("rf")
                    self.scaler = model_obj.get("scaler")
                else:
                    self.rf_model = model_obj
                    self.scaler = None

                if not self.rf_model:
                    logger.error("Could not extract Random Forest classifier from loaded model.")
                    return

                if not shap:
                    logger.warning("SHAP library is not available. Explanations will not be generated.")
                    return

                try:
                    # Initialize SHAP TreeExplainer for Random Forest
                    self.explainer = shap.TreeExplainer(self.rf_model)
                    logger.info("SHAP explainer initialized.")
                except (ValueError, TypeError, RuntimeError) as e:
                    logger.error("Failed to initialize SHAP explainer: %s", e)
            else:
                logger.error("Could not load model for SHAP.")

    def explain_prediction(
        self, event_data: Dict[str, Any], top_n: int = 5
    ) -> Dict[str, Any]:
        """
        Explain why a specific prediction was assigned its threat score.
        Calculates SHAP values for the specific event features.
        """
        self._initialize()

        if not self.explainer:
            return {"error": "Explainer not initialized"}

        try:
            # 1. Extract feature vector matching training structure (12 clean features)
            features = self.feature_extractor.extract_features(event_data)
            df = pd.DataFrame([features], columns=self.feature_names)

            # 2. Scale features if scaler is present
            if hasattr(self, "scaler") and self.scaler is not None:
                X_for_shap = self.scaler.transform(df)
            else:
                X_for_shap = df

            # 3. Calculate SHAP values
            shap_values = self.explainer.shap_values(X_for_shap)

            # Handle SHAP output shapes across library versions
            if isinstance(shap_values, list) and len(shap_values) > 1:
                target_shap = shap_values[1][0]
            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
                target_shap = shap_values[0, :, 1]
            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 2:
                target_shap = shap_values[0]
            else:
                target_shap = shap_values

            # 4. Associate SHAP values with Feature Names
            feature_importances = []
            for name, val in zip(self.feature_names, target_shap):
                f_val = features[name] if isinstance(features, dict) else features[self.feature_names.index(name)]
                feature_importances.append(
                    {
                        "feature": name,
                        "value_in_event": float(f_val),
                        "contribution": float(val),
                    }
                )

            # 5. Sort by absolute contribution to find the most impactful features
            feature_importances.sort(key=lambda x: abs(x["contribution"]), reverse=True)
            top_features = feature_importances[:top_n]

            # Provide a human-readable summary
            if isinstance(self.explainer.expected_value, (list, np.ndarray)):
                base_value = float(
                    self.explainer.expected_value[1]
                    if len(self.explainer.expected_value) > 1
                    else self.explainer.expected_value[0]
                )
            else:
                base_value = float(self.explainer.expected_value)

            prediction = base_value + float(sum(target_shap))

            reasons = []
            for imp in top_features:
                if imp["contribution"] > 0.05:
                    reasons.append(
                        f"High risk driven by `{imp['feature']}` ({imp['value_in_event']})"
                    )
                elif imp["contribution"] < -0.05:
                    reasons.append(
                        f"Risk mitigated by `{imp['feature']}` ({imp['value_in_event']})"
                    )

            return {
                "base_score": round(base_value, 4),
                "calculated_score": round(max(0.0, min(1.0, prediction)), 4),
                "top_features": top_features,
                "summary": (
                    " | ".join(reasons)
                    if reasons
                    else "No dominant distinguishing features detected."
                ),
            }

        except (ValueError, KeyError, AttributeError, RuntimeError) as e:
            logger.error("Failed to generate SHAP explanation: %s", e)
            return {"error": str(e)}


# Singleton Explainer
explainer_service = ModelExplainer()
