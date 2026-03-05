import os
import sys
import pickle
import numpy as np
import pandas as pd
from sqlalchemy import create_engine
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

# Setup paths
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.database import DATABASE_URL

SEQ_LENGTH = 50

def extract_features(df):
    """
    Extract temporal and contextual features from a grouped dataframe of an IP.
    """
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    
    # Time diff in seconds
    df["inter_arrival_time"] = df["timestamp"].diff().dt.total_seconds().fillna(0)
    
    # Cumulative failure count proxy (mocked by checking if event string contains 'fail' or 'brute')
    df["failed_auth"] = df["event"].astype(str).str.contains("fail|brute|unauthorized", case=False).astype(int)
    df["failed_auth_count"] = df["failed_auth"].cumsum()
    
    # Expanding unique ports count
    df["unique_ports_accessed"] = df["dst_port"].expanding().apply(lambda x: len(np.unique(x)))
    
    return df

def prepare_data():
    print("Connecting to database...")
    engine = create_engine(DATABASE_URL)
    
    # Query logs (limit to last 500,000 for memory efficiency)
    query = """
    SELECT id, timestamp, src_ip, dst_port, protocol, length, attack_type, threat_level, event
    FROM packet_logs
    WHERE src_ip IS NOT NULL AND timestamp IS NOT NULL
    ORDER BY timestamp ASC
    LIMIT 500000
    """
    
    print("Loading data into Pandas DataFrame...")
    try:
        df = pd.read_sql(query, engine)
    except Exception as e:
        print(f"Error reading from DB: {e}")
        # Build dummy frame if DB lacks table (for testing)
        df = pd.DataFrame(columns=["id", "timestamp", "src_ip", "dst_port", "protocol", "length", "attack_type", "threat_level", "event"])
        
    print(f"Loaded {len(df)} records. Applying feature engineering...")
    
    if len(df) == 0:
        print("Warning: Database empty. Generating dummy data for training pipeline validity.")
        # Dummy generation
        base_time = pd.Timestamp.utcnow()
        dummy_records = []
        for i in range(10000):
            dummy_records.append({
                "id": i,
                "timestamp": base_time + pd.Timedelta(seconds=i),
                "src_ip": f"10.0.0.{i%10}",
                "dst_port": 80,
                "protocol": "TCP",
                "length": 64,
                "attack_type": "BENIGN" if i % 10 != 0 else "DOS",
                "threat_level": "LOW" if i % 10 != 0 else "HIGH",
                "event": "Test"
            })
        df = pd.DataFrame(dummy_records)

    # 1. Encoding
    # Threat Level Mapping
    tl_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    df["threat_label"] = df["threat_level"].map(tl_map).fillna(0).astype(int)
    
    # 2. Extract temporal features per IP
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.groupby("src_ip").apply(extract_features).reset_index(drop=True)
    
    # 3. Handle categorical encoding (One-Hot)
    # Protocol
    df = pd.get_dummies(df, columns=["protocol"], prefix="proto", dummy_na=False)
    # Attack Type (Just encode top 5 to avoid explosion)
    top_attacks = df["attack_type"].value_counts().nlargest(5).index
    df["attack_type_clean"] = df["attack_type"].where(df["attack_type"].isin(top_attacks), "OTHER")
    df = pd.get_dummies(df, columns=["attack_type_clean"], prefix="atk", dummy_na=False)
    
    # 4. Normalization
    scaler = StandardScaler()
    num_cols = ["length", "inter_arrival_time", "failed_auth_count", "unique_ports_accessed"]
    df[num_cols] = scaler.fit_transform(df[num_cols].fillna(0))
    
    # Get all feature columns
    exclude = ["id", "timestamp", "src_ip", "dst_port", "attack_type", "threat_level", "event", "threat_label", "failed_auth"]
    feature_cols = [c for c in df.columns if c not in exclude]
    
    print(f"Features dimension: {len(feature_cols)}. Building sliding sequences...")

    # 5. Sliding Windows
    X, y = [], []
    
    for ip, group in df.groupby("src_ip"):
        group = group.sort_values("timestamp")
        
        # Need at least SEQ_LENGTH events
        if len(group) <= SEQ_LENGTH:
            continue
            
        features = group[feature_cols].values
        labels = group["threat_label"].values
        
        # Create sliding windows
        for i in range(len(features) - SEQ_LENGTH):
            X.append(features[i : i + SEQ_LENGTH])
            y.append(labels[i + SEQ_LENGTH]) # Predict next event threat level

    X = np.array(X)
    y = np.array(y)
    
    print(f"Generated {len(X)} sequences of shape {X.shape if len(X) > 0 else (0,)}.")

    if len(X) == 0:
        print("Not enough sequences. Please generate more traffic.")
        sys.exit(1)

    # 6. Train/Val/Test Split (70/15/15)
    X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.15, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.1765, random_state=42) # 0.15/0.85 approx 0.1765

    # 7. Save to pickle
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'ml_models'))
    os.makedirs(out_dir, exist_ok=True)
    
    out_path = os.path.join(out_dir, "lstm_training_data.pkl")
    with open(out_path, "wb") as f:
        pickle.dump({
            "X_train": X_train, "y_train": y_train,
            "X_val": X_val, "y_val": y_val,
            "X_test": X_test, "y_test": y_test,
            "feature_cols": feature_cols,
            "scaler": scaler
        }, f)
        
    print(f"Saved sequential data to {out_path}.")
    print(f"Train: {X_train.shape[0]}, Val: {X_val.shape[0]}, Test: {X_test.shape[0]}")

if __name__ == "__main__":
    prepare_data()
