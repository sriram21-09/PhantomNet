import pandas as pd
import random
import os
from datetime import datetime
from backend.ml.preprocessing import DataPreprocessor

# Ensure data directory exists
if not os.path.exists("data"):
    os.makedirs("data")

def generate_mock_data(n_samples=220):
    logs = []
    labels = []
    
    services = ["SSH", "HTTP", "FTP", "SMTP"]
    
    for _ in range(n_samples):
        # 80% Normal (0), 20% Anomalous (1)
        is_attack = random.random() < 0.2
        label = 1 if is_attack else 0
        
        # Base Log Structure
        log = {
            "timestamp": datetime.now().isoformat(),
            "attacker_ip": f"192.168.1.{random.randint(2, 254)}" if not is_attack else f"10.0.{random.randint(0,255)}.{random.randint(0,255)}",
            "service_type": random.choice(services),
            "headers": {"User-Agent": "Mozilla"}
        }

        if is_attack:
            # Attack Characteristics
            log["packet_count"] = random.randint(1000, 5000)
            log["payload_size"] = random.randint(5000, 20000)
            log["status"] = "Failed"
            log["payload"] = "UNION SELECT * FROM users" if log["service_type"] == "HTTP" else "root...admin...password"
        else:
            # Normal Characteristics
            log["packet_count"] = random.randint(10, 100)
            log["payload_size"] = random.randint(100, 1000)
            log["status"] = "Success"
            log["payload"] = "GET /index.html"

        logs.append(log)
        labels.append(label)

    return logs, labels

if __name__ == "__main__":
    print("🔄 Generating 220 Mock Events...")
    logs, labels = generate_mock_data(220)
    
    print("⚙️ Preprocessing and Scaling...")
    preprocessor = DataPreprocessor()
    X, y = preprocessor.process_and_label(logs, labels)
    
    # Save to CSV
    # Create DataFrame from the numpy matrix
    cols = [f"feature_{i}" for i in range(X.shape[1])]
    df = pd.DataFrame(X, columns=cols)
    df["label"] = y
    
    df.to_csv("data/training_dataset.csv", index=False)
    print(f"✅ Dataset Saved: data/training_dataset.csv ({len(df)} rows)")
