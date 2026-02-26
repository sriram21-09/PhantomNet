import sys
import os
import random
import numpy as np
import joblib
from datetime import datetime, timedelta

# Fix path: Add the project root to sys.path
# This assumes the script is run from project root, e.g. "python backend/ml/retrain_isolation_forest.py"
# We need to add the current directory (project root) to sys.path if it's not there
# OR meaningful relative imports.
# The safest way for "backend.ml.anomaly_detector" to work is if "backend" is a package in sys.path.
# If we run from project root, "backend" is a folder in . 
sys.path.append(os.getcwd())

try:
    from backend.ml.anomaly_detector import AnomalyDetector
    from backend.ml.feature_extractor import FeatureExtractor
except ImportError:
    # Fallback if run from inside backend/ml
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    from backend.ml.anomaly_detector import AnomalyDetector
    from backend.ml.feature_extractor import FeatureExtractor

def generate_mock_logs(n_samples=500):
    logs = []
    
    # Define some recurring IPs to test rate/variance features
    attacker_ips = [f"192.168.1.{i}" for i in range(10, 20)]
    normal_ips = [f"10.0.0.{i}" for i in range(50, 100)]
    
    start_time = datetime.now()
    
    for i in range(n_samples):
        is_attack = random.random() < 0.1
        current_ip = random.choice(attacker_ips) if is_attack else random.choice(normal_ips)
        
        # Vary timestamp slightly to create sessions
        event_time = start_time - timedelta(minutes=random.randint(0, 600))
        
        log = {
            "src_ip": current_ip,
            "timestamp": event_time.isoformat(),
            "length": random.randint(500, 2000) if is_attack else random.randint(50, 500),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "dst_port": random.choice([22, 80, 443, 2222, 8080, 21, 25]) if is_attack else random.randint(1024, 65535),
            "threat_score": random.uniform(5.0, 10.0) if is_attack else 0.0,
            "is_malicious": is_attack,
            "attack_type": random.choice(["brute_force", "sqli", "scan"]) if is_attack else "benign",
            "dst_ip": "172.16.0.2",
            "honeypot_type": random.choice(["SSH", "HTTP", "FTP", "SMTP"]),
            "event_type": "activity"
        }
        logs.append(log)
        
    return logs

def retrain_model():
    print("🔄 Generating 500 mock logs...")
    logs = generate_mock_logs(500)
    
    print("🧠 Initializing AnomalyDetector...")
    detector = AnomalyDetector()
    
    # Verify feature count
    extractor = FeatureExtractor()
    sample_features = extractor.extract_features(logs[0])
    print(f"📊 Features extracted per log: {len(sample_features)}")
    print(f"📋 Feature list: {list(sample_features.keys())}")
    
    if len(sample_features) != 15:
        print(f"❌ Error: Feature count is {len(sample_features)}, expected 15!")
        return
        
    print("🚀 Training model...")
    detector.train(logs)
    
    # Reload to verify
    print("💾 Verifying saved model...")
    
    model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
    loaded_model = joblib.load(model_path)
    print(f"✅ Model successfully retrained with {loaded_model.n_features_in_} features!")

if __name__ == "__main__":
    retrain_model()
