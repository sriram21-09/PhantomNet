import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Union, List

class EnsemblePredictor:
    def __init__(self, rf_path: str = None, if_path: str = None, w_rf: float = 0.7, w_if: float = 0.3):
        # Default paths
        if rf_path is None:
            rf_path = os.path.join(os.path.dirname(__file__), "attack_classifier_v2_optimized.pkl")
        if if_path is None:
            # Look for IF model
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            if_path = os.path.join(base_dir, "models", "isolation_forest_v1.pkl")
            if not os.path.exists(if_path):
                 if_path = os.path.join(os.path.dirname(__file__), "isolation_forest_v1.pkl")
                 
        self.rf_path = rf_path
        self.if_path = if_path
        self.w_rf = w_rf
        self.w_if = w_if
        
        self.rf_model = None
        self.if_model = None
        self._load_models()

    def _load_models(self):
        try:
            if os.path.exists(self.rf_path):
                self.rf_model = joblib.load(self.rf_path)
            else:
                print(f"Warning: RF model not found at {self.rf_path}")
                
            if os.path.exists(self.if_path):
                self.if_model = joblib.load(self.if_path)
            else:
                print(f"Warning: IF model not found at {self.if_path}")
        except Exception as e:
            print(f"Error loading models: {e}")

    def predict(self, rf_features: np.ndarray, if_features: np.ndarray) -> Dict[str, Union[int, float]]:
        """Predict for a single sample or batch using numpy arrays for both models."""
        if self.rf_model is None or self.if_model is None:
            raise ValueError("Models not fully loaded.")
            
        # Ensure 2D array
        if rf_features.ndim == 1:
            rf_features = rf_features.reshape(1, -1)
        if if_features.ndim == 1:
            if_features = if_features.reshape(1, -1)
            
        # 1. Pipeline Random Forest Prediction
        if hasattr(self.rf_model, "predict_proba"):
            rf_probs = self.rf_model.predict_proba(rf_features)[:, 1]
        else:
            # fallback
            rf_probs = self.rf_model.predict(rf_features)
        
        # 2. Isolation Forest Prediction
        if_scores_raw = self.if_model.decision_function(if_features)
        
        # Invert and normalize: IF score < 0 means anomaly. Let's map negative to high probability.
        # Normal range is roughly -0.5 to 0.5. Let's use a sigmoid-like curve.
        S_if = 1.0 / (1.0 + np.exp(if_scores_raw * 5.0)) # scale factor to stretch into 0-1
        
        # 3. Ensemble Calculation
        ensemble_scores = (self.w_rf * rf_probs) + (self.w_if * S_if)
        predictions = (ensemble_scores >= 0.5).astype(int)
        
        if len(predictions) == 1:
            return {
                "prediction": int(predictions[0]),
                "ensemble_score": float(ensemble_scores[0]),
                "rf_prob": float(rf_probs[0]),
                "if_score": float(S_if[0])
            }
        
        return {
            "predictions": predictions.tolist(),
            "ensemble_scores": ensemble_scores.tolist(),
            "rf_probs": rf_probs.tolist(),
            "if_scores": S_if.tolist()
        }
        
    def predict_batch(self, rf_features_df: pd.DataFrame, if_features_df: pd.DataFrame) -> pd.DataFrame:
        """Batch prediction returning a DataFrame with scores appended."""
        res = self.predict(rf_features_df.values, if_features_df.values)
        
        out_df = rf_features_df.copy()
        out_df['rf_prob'] = res['rf_probs']
        out_df['if_score'] = res['if_scores']
        out_df['ensemble_score'] = res['ensemble_scores']
        out_df['ensemble_prediction'] = res['predictions']
        return out_df

if __name__ == "__main__":
    # Smoke test
    try:
        predictor = EnsemblePredictor()
        print("Models loaded successfully.")
        
        # Inference dimension check
        rf_dim = getattr(predictor.rf_model.named_steps["scaler"], "n_features_in_", 12) if hasattr(predictor.rf_model, "named_steps") else 12
        if_dim = getattr(predictor.if_model, "n_features_in_", 15)
                 
        rf_dummy = np.random.rand(5, rf_dim)
        if_dummy = np.random.rand(5, if_dim)
        res = predictor.predict(rf_dummy, if_dummy)
        print("Smoke test prediction block lengths:", len(res["predictions"]))
    except Exception as e:
        print(f"Smoke test failed: {e}")
