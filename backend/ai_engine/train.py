import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import sys

# Fix import path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.feature_extractor import FeatureExtractor

# --- CONFIGURATION ---
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model_rf.pkl")
FEATURE_NAMES = ['Duration', 'Internal_Traffic', 'Same_Subnet', 'TCP', 'UDP', 'ICMP']

def generate_training_data(n_samples=2000):
    """Generates larger dataset for better validation."""
    extractor = FeatureExtractor()
    data = []
    labels = []

    print(f"⚡ Generating {n_samples} synthetic packets...")
    
    for _ in range(n_samples):
        is_malicious = np.random.rand() > 0.5
        
        if is_malicious:
            # Attack Profile
            duration = np.random.uniform(0, 0.5) 
            protocol = np.random.choice(['UDP', 'TCP'])
            src_ip = "192.168.1.100" 
            dst_ip = "192.168.1.5"
            label = 1
        else:
            # Normal Profile
            duration = np.random.uniform(0.1, 5.0)
            protocol = 'TCP'
            src_ip = "192.168.1.5"
            dst_ip = "8.8.8.8"
            label = 0

        # Extract
        norm_dur = extractor.normalize(duration, 'duration')
        proto_vec = extractor.encode_protocol(protocol)
        ip_vec = extractor.extract_ip_patterns(src_ip, dst_ip)
        
        # [Duration, Internal, SameSubnet, TCP, UDP, ICMP]
        features = [norm_dur, ip_vec[0], ip_vec[1]] + proto_vec
        
        data.append(features)
        labels.append(label)

    return np.array(data), np.array(labels)

def train_and_evaluate():
    # 1. Get Data
    X, y = generate_training_data()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 2. Initialize Model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    
    # 3. Cross-Validation (5-Fold)
    print("\n🔄 Performing 5-Fold Cross-Validation...")
    cv_scores = cross_val_score(clf, X, y, cv=5)
    print(f"   Scores: {cv_scores}")
    print(f"   Mean Accuracy: {cv_scores.mean() * 100:.2f}%")

    if cv_scores.mean() < 0.80:
        print("❌ Model failed validation (<80%). Keeping old model.")
        return

    # 4. Final Training
    print("\n🚀 Training Final Model...")
    clf.fit(X_train, y_train)
    
    # 5. Detailed Evaluation
    preds = clf.predict(X_test)
    print("\n📊 Classification Report:")
    print(classification_report(y_test, preds, target_names=['BENIGN', 'MALICIOUS']))
    
    # 6. Feature Importance
    print("\n🔑 Feature Importance:")
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for f in range(X.shape[1]):
        print(f"   {f+1}. {FEATURE_NAMES[indices[f]]}: {importances[indices[f]]:.4f}")

    # 7. Save Model
    joblib.dump(clf, MODEL_PATH)
    print(f"\n✅ High-Accuracy Model Saved to: {MODEL_PATH}")

if __name__ == "__main__":
    train_and_evaluate()