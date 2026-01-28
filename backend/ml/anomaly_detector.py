import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from backend.ml.feature_extractor import FeatureExtractor

# Path to save the trained model
MODEL_PATH = "backend/ml/model.pkl"

class AnomalyDetector:
    def __init__(self):
        # The Brain: Isolation Forest
        # contamination=0.1 means we expect ~10% of traffic to be attacks
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.extractor = FeatureExtractor()
        self.is_trained = False

    def train(self, logs):
        """
        Trains the model on a batch of historical logs.
        """
        print(f"🧠 Training on {len(logs)} logs...")
        
        # 1. Convert list of dicts -> Matrix of features (X)
        if not logs:
            print("⚠️ No logs to train on.")
            return

        X = [self.extractor.extract_features(log) for log in logs]
        X = np.array(X)

        # 2. Train the Isolation Forest
        self.model.fit(X)
        self.is_trained = True
        
        # 3. Save the brain to disk
        joblib.dump(self.model, MODEL_PATH)
        print("✅ Model trained and saved.")

    def predict(self, log_entry):
        """
        Returns (prediction, anomaly_score)
        Prediction: -1 (Anomaly), 1 (Normal)
        """
        if not self.is_trained:
            # Try to load existing model
            if not self.load():
                # Default to 'Normal' (1) if no brain exists yet
                return 1, 0.0

        # Extract features for single log
        features = self.extractor.extract_features(log_entry)
        # Reshape for sklearn (1, N_features)
        vector = features.reshape(1, -1)
        
        # Predict
        pred = self.model.predict(vector)[0]
        score = self.model.decision_function(vector)[0]
        
        return pred, score

    def load(self):
        """Loads a saved model from disk."""
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.is_trained = True
            return True
        return False