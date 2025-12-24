import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import sys

# Setup paths
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.feature_extractor import FeatureExtractor

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model_rf.pkl")
FEATURE_NAMES = ['Duration', 'Internal_Traffic', 'Same_Subnet', 'TCP', 'UDP', 'ICMP']

def generate_balanced_data(n_samples=6000):
    extractor = FeatureExtractor()
    data = []
    labels = []

    print(f"⚡ Generating {n_samples} samples (Teaching that Fast Packets are OK)...")
    
    for _ in range(n_samples):
        # 20% Malicious, 80% Benign
        is_malicious = np.random.rand() < 0.2
        
        if is_malicious:
            # === TRUE ATTACKS ===
            # Attackers are weird: They use consistent, mechanical timing or rare ports
            # We differentiate by IP Pattern mostly now, since Duration is unreliable
            duration = np.random.uniform(0, 0.01) # Extremely fast
            protocol = 'TCP' 
            src_ip = f"{np.random.randint(1, 200)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}"
            dst_ip = "192.168.29.49"
            label = 1
        else:
            # === BENIGN PROFILES ===
            profile = np.random.choice(['fast_web', 'slow_web', 'azure', 'local'])
            
            if profile == 'fast_web':
                # *** THE FIX ***: Normal packets can also be fast (ACKs, Handshakes)
                # Matches the Sniffer's hardcoded 0.1s
                duration = np.random.uniform(0.05, 0.3) 
                protocol = 'TCP'
                src_ip = "192.168.29.49"
                dst_ip = "142.250.1.1" # Google
            
            elif profile == 'slow_web':
                # Heavy downloads
                duration = np.random.uniform(1.0, 5.0)
                protocol = 'TCP'
                src_ip = "192.168.29.49"
                dst_ip = f"{np.random.randint(1, 200)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}"

            elif profile == 'azure':
                # Microsoft/GitHub Background noise
                duration = np.random.uniform(0.1, 1.0)
                protocol = 'TCP'
                src_ip = "140.82.113.25" # GitHub
                dst_ip = "192.168.29.49"
                
            elif profile == 'local':
                duration = 0.1
                protocol = 'UDP' 
                src_ip = "192.168.29.49"
                dst_ip = "192.168.29.255"

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
    X, y = generate_balanced_data()
    
    # Train
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    
    # Feature Importance
    print("\n📊 Feature Importance:")
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for f in range(X.shape[1]):
        print(f"   {f+1}. {FEATURE_NAMES[indices[f]]}: {importances[indices[f]]:.4f}")

    joblib.dump(clf, MODEL_PATH)
    print(f"\n✅ Reality-Check Model Saved to: {MODEL_PATH}")

if __name__ == "__main__":
    train()