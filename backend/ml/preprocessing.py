import numpy as np
import pandas as pd
import joblib
import os
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from backend.ml.feature_extractor import FeatureExtractor

MODEL_DIR = "backend/ml/"

class DataPreprocessor:
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.scaler = StandardScaler()
        self.is_fitted = False
        
    def process_and_label(self, raw_logs, labels=None):
        """
        Converts raw logs -> Feature Vectors -> Scaled Matrix.
        If labels are provided, returns (X, y).
        If no labels (inference mode), returns X.
        """
        # 1. Extract Features (Raw Vectors)
        vectors = []
        valid_labels = []
        
        for i, log in enumerate(raw_logs):
            try:
                vec = self.extractor.extract_features(log)
                # Handle NaNs (Simple Imputation: replace with 0)
                vec = np.nan_to_num(vec)
                vectors.append(vec)
                if labels is not None:
                    valid_labels.append(labels[i])
            except Exception as e:
                print(f"⚠️ Skipping bad log: {e}")

        X = np.array(vectors)

        # 2. Scale Features (Fit on training data, Transform on new data)
        if labels is not None:
            # Training Mode: Learn the scaling parameters
            X_scaled = self.scaler.fit_transform(X)
            self.save_scaler()
            return X_scaled, np.array(valid_labels)
        else:
            # Inference Mode: Use existing scaling parameters
            if not self.is_fitted:
                self.load_scaler()
            X_scaled = self.scaler.transform(X)
            return X_scaled

    def save_scaler(self):
        joblib.dump(self.scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
        self.is_fitted = True

    def load_scaler(self):
        path = os.path.join(MODEL_DIR, "scaler.pkl")
        if os.path.exists(path):
            self.scaler = joblib.load(path)
            self.is_fitted = True
        else:
            print("⚠️ Warning: No scaler found. Using raw data (suboptimal).")
            self.is_fitted = False
