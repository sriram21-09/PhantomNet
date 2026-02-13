import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from sklearn.ensemble import IsolationForest
import joblib
import os
from dotenv import load_dotenv

load_dotenv()
# Force correct connection string inside container
DATABASE_URL = "postgresql://postgres:postgres@phantomnet_postgres:5432/phantomnet"

# Features to train on
FEATURES = ['src_port', 'dst_port', 'protocol_num']
MODEL_PATH = "models/isolation_forest_v1.pkl"

def get_data():
    try:
        print("?? Connecting to Database...")
        engine = create_engine(DATABASE_URL)
        # Try to get real logs
        try:
            df = pd.read_sql("SELECT * FROM logs", engine)
        except:
            df = pd.DataFrame() # Table might not exist yet

        if df.empty:
            print("??  Database empty. Generating MOCK training data...")
            # Mock Normal Traffic
            normal = pd.DataFrame({
                'src_port': np.random.randint(1024, 65535, 1000),
                'dst_port': np.random.choice([80, 443, 8080], 1000),
                'protocol_num': [0] * 1000
            })
            # Mock Attack Traffic
            attack = pd.DataFrame({
                'src_port': np.random.randint(1024, 65535, 50),
                'dst_port': np.random.choice([22, 23, 3389], 50),
                'protocol_num': [0] * 50
            })
            return pd.concat([normal, attack], ignore_index=True)
            
        print(f"? Loaded {len(df)} records from Database.")
        return df

    except Exception as e:
        print(f"? Connection Failed: {e}")
        return pd.DataFrame()

def train():
    print("?? Fetching Data...")
    df = get_data()
    
    # Preprocessing
    if 'protocol_num' not in df.columns:
        df['protocol_num'] = 0
    
    print(f"?? Training Isolation Forest on {len(df)} samples...")
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    clf.fit(df[FEATURES])
    
    # Validation
    scores = clf.decision_function(df[FEATURES])
    print(f"?? Validation Scores (Mean): {scores.mean():.4f}")
    
    # Save
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"?? Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
