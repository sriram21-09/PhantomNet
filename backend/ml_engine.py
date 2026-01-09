import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier

# CONFIGURATION
MODEL_FILE = "traffic_model.pkl"

class ThreatDetector:
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.load_model()

    def load_model(self):
        """Attempts to load a saved model from disk."""
        if os.path.exists(MODEL_FILE):
            print(f"🧠 ML Engine: Loading saved model from {MODEL_FILE}...")
            try:
                self.model = joblib.load(MODEL_FILE)
                self.is_trained = True
                print("   ✅ Model loaded successfully.")
            except Exception as e:
                print(f"   ⚠️ Failed to load model: {e}")
        else:
            print("🧠 ML Engine: No saved model found. Waiting for training data.")

    def train(self, data):
        """
        Trains the Random Forest model and saves it to disk.
        Expected data format: List of dictionaries or Pandas DataFrame
        """
        print("🧠 ML Engine: Starting training sequence...")
        df = pd.DataFrame(data)
        
        # Feature Selection (Must match what we use for prediction)
        # We convert protocols to numbers for the AI: TCP=0, UDP=1, ICMP=2
        df['protocol_num'] = df['protocol'].map({'TCP': 0, 'UDP': 1, 'ICMP': 2}).fillna(0)
        
        features = df[['protocol_num', 'length']]
        labels = df['is_malicious'] # This requires labeled training data

        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(features, labels)
        self.is_trained = True
        
        # SAVE THE BRAIN 💾
        joblib.dump(self.model, MODEL_FILE)
        print(f"   ✅ Training complete. Model saved to {MODEL_FILE}")

    def predict(self, packet_data):
        """
        Returns (is_malicious: bool, confidence: float)
        """
        if not self.is_trained:
            # Fallback if no model exists yet
            return False, 0.0

        # Pre-process single packet
        proto_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2}
        proto_num = proto_map.get(packet_data.get('protocol', 'TCP'), 0)
        
        features = pd.DataFrame([[proto_num, packet_data['length']]], 
                              columns=['protocol_num', 'length'])
        
        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0][1] # Probability of being "True" (Malicious)
        
        return bool(prediction), float(probability)