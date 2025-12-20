import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os
import sys

# Fix import path to allow importing from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.feature_extractor import FeatureExtractor

def generate_training_data(n_samples=1000):
    """Generates synthetic traffic data for training."""
    extractor = FeatureExtractor()
    data = []
    labels = []

    for _ in range(n_samples):
        # 50/50 chance of being Malicious
        is_malicious = np.random.rand() > 0.5
        
        if is_malicious:
            # Attack Profile: Short duration, Random High Ports, UDP often
            duration = np.random.uniform(0, 0.5) 
            protocol = np.random.choice(['UDP', 'TCP'])
            src_ip = "192.168.1.100" # Attacker
            dst_ip = "192.168.1.5"   # Victim
            label = 1 # 1 = MALICIOUS
        else:
            # Normal Profile: Longer duration, HTTPS/HTTP (TCP)
            duration = np.random.uniform(0.1, 5.0)
            protocol = 'TCP'
            src_ip = "192.168.1.5"
            dst_ip = "8.8.8.8"
            label = 0 # 0 = BENIGN

        # Extract Features manually for training
        norm_dur = extractor.normalize(duration, 'duration')
        proto_vec = extractor.encode_protocol(protocol)
        ip_vec = extractor.extract_ip_patterns(src_ip, dst_ip)
        
        # Feature Vector: [Duration, Internal, SameSubnet, TCP, UDP, ICMP]
        features = [norm_dur, ip_vec[0], ip_vec[1]] + proto_vec
        
        data.append(features)
        labels.append(label)

    return np.array(data), np.array(labels)

def train():
    print("🧠 Generating synthetic training data...")
    X, y = generate_training_data()
    
    # Split: 80% for training, 20% for testing
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Initialize Random Forest (The Brain)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    
    print("💪 Training the Random Forest model...")
    clf.fit(X_train, y_train)
    
    # Validate Accuracy
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"🎯 Model Accuracy: {acc * 100:.2f}%")
    
    if acc < 0.80:
        print("⚠️ Warning: Accuracy is too low!")
    else:
        # Save the model
        model_path = os.path.join(os.path.dirname(__file__), "model_rf.pkl")
        joblib.dump(clf, model_path)
        print(f"✅ Model saved to: {model_path}")

if __name__ == "__main__":
    train()