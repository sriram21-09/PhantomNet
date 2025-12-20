import joblib
import os
import numpy as np

class ThreatDetector:
    def __init__(self):
        # Path to the model file
        # It looks for backend/ai_engine/model_rf.pkl
        self.model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ai_engine", "model_rf.pkl")
        self.model = None
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            print("✅ AI Model Loaded Successfully")
        else:
            print(f"⚠️ Model file not found at: {self.model_path}")
            print("Did you run 'python ai_engine/train.py'?")

    def predict(self, feature_vector):
        """
        Returns:
            prediction (str): "MALICIOUS" or "BENIGN"
            threat_score (float): 0.0 to 1.0 (Probability of attack)
        """
        if not self.model:
            return "UNKNOWN", 0.0

        # Reshape for a single sample prediction
        vector = np.array(feature_vector).reshape(1, -1)
        
        # Get probability (Threat Score)
        try:
            probs = self.model.predict_proba(vector)[0]
            threat_score = probs[1] # Probability of being class 1 (Malicious)
            
            # Threshold: If score > 50%, it's malicious
            prediction = "MALICIOUS" if threat_score > 0.5 else "BENIGN"
            return prediction, round(threat_score, 4)
        except Exception as e:
            print(f"Prediction Error: {e}")
            return "ERROR", 0.0