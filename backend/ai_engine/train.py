import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
import sys

# Setup paths
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.feature_extractor import FeatureExtractor

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model_rf.pkl")
FEATURE_NAMES = ['Duration', 'Internal_Traffic', 'Same_Subnet', 'TCP', 'UDP', 'ICMP']

def generate_fix_data(n_samples=5000):
    extractor = FeatureExtractor()
    data = []
    labels = []

    print(f"⚡ Generating {n_samples} samples (Heavily weighted for UDP Broadcasts)...")
    
    for _ in range(n_samples):
        # 20% Malicious, 80% Benign (To cure the paranoia)
        is_malicious = np.random.rand() < 0.2
        
        if is_malicious:
            # === REAL ATTACKS ===
            # Attackers usually come from OUTSIDE, or use strange ports
            duration = np.random.uniform(0, 0.5)
            protocol = 'TCP' # Change malicious to mostly TCP to break UDP bias
            src_ip = "45.33.12.10"
            dst_ip = "192.168.29.154"
            label = 1
        else:
            # === BENIGN TRAFFIC (The Cure) ===
            # We force 60% of ALL traffic to be UDP Broadcasts
            if np.random.rand() > 0.4:
                # The exact pattern you see in logs
                duration = 0.1
                protocol = 'UDP'
                src_ip = "192.168.29.154"
                dst_ip = "192.168.29.255" # Broadcast
            else:
                # Normal Web
                duration = np.random.uniform(0.1, 5.0)
                protocol = 'TCP'
                src_ip = "192.168.29.154"
                dst_ip = "8.8.8.8"

            label = 0

        # Extract
        norm_dur = extractor.normalize(duration, 'duration')
        proto_vec = extractor.encode_protocol(protocol)
        ip_vec = extractor.extract_ip_patterns(src_ip, dst_ip)
        
        features = [norm_dur, ip_vec[0], ip_vec[1]] + proto_vec
        data.append(features)
        labels.append(label)

    return np.array(data), np.array(labels)

def train():
    X, y = generate_fix_data()
    
    # Train
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    
    # Evaluate
    print("\n📊 Feature Importance (Should see UDP drop in rank):")
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]
    for f in range(X.shape[1]):
        print(f"   {f+1}. {FEATURE_NAMES[indices[f]]}: {importances[indices[f]]:.4f}")

    joblib.dump(clf, MODEL_PATH)
    print(f"\n✅ Fixed Model Saved to: {MODEL_PATH}")

if __name__ == "__main__":
    train()
