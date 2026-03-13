import time
import pandas as pd
import numpy as np
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.ml.feature_extractor import FeatureExtractor
from ml.feature_engineering_vectorized import VectorizedFeatureExtractor

def generate_dummy_events(n=10000):
    now = pd.Timestamp.utcnow()
    timestamps = [now - pd.Timedelta(seconds=i) for i in range(n)]
    
    return pd.DataFrame({
        'src_ip': np.random.choice(['192.168.1.5', '10.0.0.1', '8.8.8.8', '1.1.1.1'], n),
        'dst_ip': np.random.choice(['192.168.1.100', '10.0.0.2'], n),
        'timestamp': timestamps,
        'length': np.random.randint(40, 1500, n),
        'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n),
        'dst_port': np.random.randint(1, 65535, n),
        'threat_score': np.random.uniform(0, 1, n),
        'is_malicious': np.random.choice([0, 1], n),
        'attack_type': np.random.choice(['None', 'DDoS', 'Scan'], n),
        'honeypot_type': np.random.choice(['None', 'Cowrie', 'Dionaea'], n)
    })

def benchmark():
    n_events = 5000
    df = generate_dummy_events(n_events)
    events_dict = df.to_dict('records')
    
    print(f"Benchmarking with {n_events} events...")
    
    # Baseline: loops + dict state
    extractor_base = FeatureExtractor()
    start_time = time.time()
    for event in events_dict:
        # Convert timestamp to string if expected
        event['timestamp'] = str(event['timestamp'])
        extractor_base.extract_features(event)
    base_time = time.time() - start_time
    print(f"Baseline (loop/dict) Time: {base_time:.4f} sec")
    
    # Vectorized
    extractor_vec = VectorizedFeatureExtractor()
    start_time = time.time()
    features_df = extractor_vec.extract_features_batch(df)
    vec_time = time.time() - start_time
    print(f"Vectorized Time: {vec_time:.4f} sec")
    
    speedup = ((base_time - vec_time) / base_time) * 100
    print(f"Speedup: {speedup:.2f}% (Target: 40%+ faster)")
    
if __name__ == "__main__":
    benchmark()
