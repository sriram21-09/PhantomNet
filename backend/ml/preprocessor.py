import numpy as np
import pickle
import os
from sklearn.preprocessing import StandardScaler, MinMaxScaler

class LogPreprocessor:
    """
    Scales and normalizes feature vectors so they are ready for the AI model.
    """

    def __init__(self):
        # StandardScaler for unbounded features (Time delta, Entropy)
        # Centers data around 0 with a standard deviation of 1
        self.standard_scaler = StandardScaler()
        
        # MinMaxScaler for bounded features (Hour, Day, Counts)
        # Squishes data between 0 and 1
        self.min_max_scaler = MinMaxScaler()
        
        # We need to know which columns go to which scaler
        # Indices based on FeatureExtractor order:
        # [0:Hour, 1:Day, 2:Delta, 3:IP_Int, 4:Port, 5:Private, 6:UserLen, 7:PassLen, 8:Entropy, 9:Admin, 10:Special]
        self.standard_cols = [2, 3, 4, 6, 7, 8, 10] # Delta, IP, Port, Lengths, Entropy
        self.min_max_cols = [0, 1, 5, 9]            # Hour, Day, Boolean flags

    def fit(self, X):
        """
        'Learns' the max/min and mean of the training data.
        X should be a 2D numpy array (list of vectors).
        """
        if len(X) == 0:
            return

        # Split data columns
        X_std = X[:, self.standard_cols]
        X_mm = X[:, self.min_max_cols]

        # Learn parameters
        self.standard_scaler.fit(X_std)
        self.min_max_scaler.fit(X_mm)

    def transform(self, X):
        """
        Applies the scaling to new data.
        """
        if len(X) == 0:
            return X

        # Extract
        X_std = X[:, self.standard_cols]
        X_mm = X[:, self.min_max_cols]

        # Transform
        X_std_scaled = self.standard_scaler.transform(X_std)
        X_mm_scaled = self.min_max_scaler.transform(X_mm)

        # Reconstruct the array (concatenating them back together)
        # Note: The order changes here, but that's fine as long as consistent
        return np.hstack([X_std_scaled, X_mm_scaled])

    def save(self, filepath="backend/ml/preprocessor.pkl"):
        """Saves the trained scalers to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(filepath="backend/ml/preprocessor.pkl"):
        """Loads a saved preprocessor."""
        with open(filepath, "rb") as f:
            return pickle.load(f)
