import os
import logging
import shap
import pandas as pd
from typing import Dict, Any, List

from ml.feature_extractor import FeatureExtractor
from ml.model_loader import load_model

logger = logging.getLogger("explainability")

class ModelExplainer:
    def __init__(self):
        self.rf_model = None
        self.explainer = None
        self.feature_names = FeatureExtractor.FEATURE_NAMES
        self.feature_extractor = FeatureExtractor()
        
    def _initialize(self):
        """Lazy load the Random Forest model and TreeExplainer."""
        if not self.rf_model:
            model_components = load_model()
            if model_components and "model" in model_components:
                self.rf_model = model_components["model"]
                
                try:
                    # Initialize SHAP TreeExplainer for Random Forest
                    # We pass the underlying classifier if wrapped in a dictionary
                    self.explainer = shap.TreeExplainer(self.rf_model)
                    logger.info("SHAP explainer initialized.")
                except Exception as e:
                    logger.error(f"Failed to initialize SHAP explainer: {e}")
            else:
                logger.error("Could not load Random Forest model for SHAP.")

    def explain_prediction(self, event_data: Dict[str, Any], top_n: int = 5) -> Dict[str, Any]:
        """
        Explain why a specific prediction was assigned its threat score.
        Calculates SHAP values for the specific event features.
        """
        self._initialize()
        
        if not self.explainer:
            return {"error": "Explainer not initialized"}
            
        try:
            # 1. Extract feature vector matching training structure
            features = self.feature_extractor.extract_features(event_data)
            df = pd.DataFrame([features], columns=self.feature_names)
            
            # 2. Calculate SHAP values
            shap_values = self.explainer.shap_values(df)
            
            # Scikit-learn RandomForestClassifier shap_values often returns a list of arrays (one per class).
            # We want the explanation for the positive class (attack/threat).
            # Usually index 1 is the positive class.
            if isinstance(shap_values, list) and len(shap_values) > 1:
                target_shap = shap_values[1][0]
            else:
                # Some versions/models return a single array
                target_shap = shap_values[0] if len(np.shape(shap_values)) > 1 else shap_values
            
            # 3. Associate SHAP values with Feature Names
            feature_importances = []
            for name, val, f_val in zip(self.feature_names, target_shap, features):
                feature_importances.append({
                    "feature": name,
                    "value_in_event": float(f_val),
                    "contribution": float(val)
                })
                
            # 4. Sort by absolute contribution to find the most impactful features
            # Positive contribution pushes score higher (towards threat)
            # Negative contribution pushes score lower (towards benign)
            feature_importances.sort(key=lambda x: abs(x["contribution"]), reverse=True)
            top_features = feature_importances[:top_n]
            
            # Provide a human-readable summary
            base_value = float(self.explainer.expected_value[1]) if isinstance(self.explainer.expected_value, (list, np.ndarray)) else float(self.explainer.expected_value)
            
            # Calculate final predicted score roughly from base + sum(shap)
            prediction = base_value + sum(target_shap)
            
            reasons = []
            for imp in top_features:
                if imp["contribution"] > 0.05:
                    reasons.append(f"High risk driven by `{imp['feature']}` ({imp['value_in_event']})")
                elif imp["contribution"] < -0.05:
                    reasons.append(f"Risk mitigated by `{imp['feature']}` ({imp['value_in_event']})")
                    
            return {
                "base_score": base_value,
                "calculated_score": max(0.0, min(1.0, prediction)),
                "top_features": top_features,
                "summary": " | ".join(reasons) if reasons else "No dominant distinguishing features detected."
            }

        except Exception as e:
            logger.error(f"Failed to generate SHAP explanation: {e}")
            return {"error": str(e)}

# Singleton Explainer
explainer_service = ModelExplainer()
