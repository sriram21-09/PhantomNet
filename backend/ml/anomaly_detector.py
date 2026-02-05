import numpy as np
import joblib
import os
import time
from sklearn.ensemble import IsolationForest
from ml.feature_extractor import FeatureExtractor

# Path to save the trained model
MODEL_PATH = "backend/ml/model.pkl"


class AnomalyDetector:
    def __init__(self):
        # The Brain: Isolation Forest
        # contamination=0.1 means we expect ~10% of traffic to be attacks
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.extractor = FeatureExtractor()
        self.is_trained = False

    def train(self, logs):
        """
        Trains the model on a batch of historical logs.
        """
        print(f"🧠 Training on {len(logs)} logs...")

        if not logs:
            print("⚠️ No logs to train on.")
            return

        # Convert list of feature dicts -> numeric feature matrix
        X = []
        for log in logs:
            feature_dict = self.extractor.extract_features(log)
            feature_vector = list(feature_dict.values())  # preserve order
            X.append(feature_vector)

        X = np.array(X, dtype=float)

        # Train Isolation Forest
        self.model.fit(X)
        self.is_trained = True

        # Save trained model
        joblib.dump(self.model, MODEL_PATH)
        print("✅ Model trained and saved.")

    def predict(self, log_entry):
        """
        Returns (prediction, anomaly_score)
        Prediction: -1 (Anomaly), 1 (Normal)
        """
        if not self.is_trained:
            if not self.load():
                # Default to 'Normal' if no trained model exists
                return 1, 0.0

        # Extract features
        feature_dict = self.extractor.extract_features(log_entry)
        vector = np.array(
            list(feature_dict.values()),
            dtype=float
        ).reshape(1, -1)

        # -------- LATENCY MEASUREMENT (ML INFERENCE ONLY) --------
        start_time = time.perf_counter()

        pred = self.model.predict(vector)[0]
        score = self.model.decision_function(vector)[0]

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        print(f"[LATENCY] ML inference time: {latency_ms:.2f} ms")
        # --------------------------------------------------------

        return pred, score

    def load(self):
        """Loads a saved model from disk."""
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.is_trained = True
            return True
        return False
