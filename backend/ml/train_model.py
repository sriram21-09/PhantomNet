import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from sklearn.ensemble import IsolationForest
import joblib
import os
from dotenv import load_dotenv

# 1. Load Environment Variables (to get DB connection)
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

# --- CONFIGURATION ---
MODEL_PATH = "models/isolation_forest_v1.pkl"
# Features to train on: [Source Port, Destination Port, Protocol (0=TCP, 1=UDP)]
FEATURES = ['src_port', 'dst_port', 'protocol_num']

def get_data():
    """Fetches logs from DB. If empty, generates mock data for training."""
    try:
        print("🔌 Connecting to Database...")
        engine = create_engine(DATABASE_URL)
        
        # Query logs (Assuming table name is 'logs' or 'events')
        # Adjust table name if yours is different!
        query = "SELECT * FROM logs" 
        df = pd.read_sql(query, engine)
        
        if df.empty:
            raise ValueError("Database is empty")
            
        print(f"✅ Loaded {len(df)} records from Database.")
        return df

    except Exception as e:
        print(f"⚠️  Database read failed or empty ({e}). Generating MOCK training data...")
        # Generate fake normal traffic (Port 80/443)
        normal_data = pd.DataFrame({
            'src_port': np.random.randint(1024, 65535, 1000),
            'dst_port': np.random.choice([80, 443, 8080], 1000),
            'protocol_num': [0] * 1000  # TCP
        })
        # Generate fake attack traffic (Port 22/23 scanning)
        attack_data = pd.DataFrame({
            'src_port': np.random.randint(1024, 65535, 50),
            'dst_port': np.random.choice([22, 23, 3389], 50),
            'protocol_num': [0] * 50
        })
        return pd.concat([normal_data, attack_data], ignore_index=True)

def preprocess(df):
    """Cleans data for the model."""
    # Ensure protocol is numeric (TCP=0, UDP=1, Other=2)
    if 'protocol' in df.columns and df['protocol'].dtype == 'O':
        df['protocol_num'] = df['protocol'].map({'TCP': 0, 'UDP': 1}).fillna(2)
    elif 'protocol_num' not in df.columns:
        df['protocol_num'] = 0 # Default to TCP if missing
        
    # Ensure ports are integers
    df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0)
    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0)
    
    return df[FEATURES]

def train():
    print("🔄 Fetching Data...")
    raw_df = get_data()
    
    print("🧹 Preprocessing...")
    train_df = preprocess(raw_df)
    
    print(f"🧠 Training Isolation Forest on {len(train_df)} samples...")
    # Initialize with default parameters as requested
    clf = IsolationForest(
        n_estimators=100, 
        contamination=0.05, # Expect ~5% anomalies
        random_state=42,
        n_jobs=-1
    )
    clf.fit(train_df)
    
    # Calculate Anomaly Scores (Validation)
    scores = clf.decision_function(train_df)
    print(f"📊 Validation Scores (Mean): {scores.mean():.4f}")
    
    # Create 'models' directory if it doesn't exist
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    
    print(f"💾 Saving model to {MODEL_PATH}...")
    joblib.dump(clf, MODEL_PATH)
    print("✅ Training Complete.")

if __name__ == "__main__":
    train()