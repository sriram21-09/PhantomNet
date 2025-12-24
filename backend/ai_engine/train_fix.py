import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import os
import sys

# Setup paths
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.feature_extractor import FeatureExtractor

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model_rf.pkl")
FEATURE_NAMES = ['Duration', 'Internal_Traffic', 'Same_Subnet', 'TCP', 'UDP', 'ICMP']

def generate_random_ip():
    """Generates a random public IP address to simulate real internet."""
    return f"{np.random.randint(1, 220)}.{np.random.randint(0, 255)}.{np.random.randint(0, 255)}.{np.random.randint(0, 255)}"

def generate_fix_data(n_samples=6000):
    extractor = FeatureExtractor()
    data = []
    labels = []

    print(f"⚡ Generating {n_samples} samples (Learning that the Internet is safe)...")
    
    for _ in range(n_samples):
        # 15% Malicious, 85% Benign (Real life is mostly safe)
        is_malicious = np.random.rand() < 0.15
        
        if is_malicious:
            # === MALICIOUS PROFILES (Specific Attacks) ===
            # Attackers usually scan ports rapidly (Very short duration)
            duration = np.random.uniform(0, 0.05) 
            protocol = 'TCP' 
            src_ip = generate_random_ip()
            dst_ip = "192.168.29.49"
            label = 1
        else:
            # === BENIGN PROFILES (Real Life Noise) ===
            profile = np.random.choice(['surfing', 'update', 'broadcast', 'streaming'])
            
            if profile == 'surfing':
                # You visiting random websites
                duration = np.random.uniform(0.1, 2.0)
                protocol = 'TCP'
                src_ip = "192.168.29.49"
                dst_ip = generate_random_ip() # Random Public IP
            
            elif profile == 'update':
                # Windows Update / Background Services (Longer connections)
                duration = np.random.uniform(1.0, 5.0)
                protocol = 'TCP'
                src_ip = "192.168.29.49"
                dst_ip = generate_random_ip() # Microsoft/Azure IPs
                
            elif profile == 'broadcast':
                # Local Noise
                duration = 0.1
                protocol = 'UDP'
                src_ip = "192.168.29.49"
                dst_ip = "192.168.29.255"
                
            elif profile == 'streaming':
                # YouTube/Netflix
                duration = np.random.uniform(5.0, 30.0)
                protocol = 'UDP'
                src_ip = generate_random_ip()
                dst_ip = "192.168.29.49"

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
    
    # Feature Importance
    print("\n📊 Feature Importance:")
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for f in range(X.shape[1]):
        print(f"   {f+1}. {FEATURE_NAMES[indices[f]]}: {importances[indices[f]]:.4f}")

    joblib.dump(clf, MODEL_PATH)
    print(f"\n✅ Balanced Model Saved to: {MODEL_PATH}")