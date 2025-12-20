from fastapi import FastAPI
from services.feature_extractor import FeatureExtractor
import pandas as pd
import numpy as np

# 1. Initialize the App FIRST
app = FastAPI()

# 2. Initialize the Feature Extractor
extractor = FeatureExtractor()

# --- ROUTES ---

@app.get("/")
def read_root():
    return {"message": "PhantomNet Backend is Running"}

@app.get("/test-features")
def test_feature_extraction():
    """
    Generates sample data and runs the feature extraction pipeline.
    This proves the module is working on the dashboard.
    """
    # Generate dummy data
    raw_samples = extractor.generate_labeled_sample()
    processed_results = []
    
    # Process each sample through your new pipeline
    for sample in raw_samples:
        duration = extractor.extract_time_features(sample['start'], sample['end'])
        protocol_vec = extractor.encode_protocol(sample['proto'])
        ip_vec = extractor.extract_ip_patterns(sample['src'], sample['dst'])
        norm_dur = extractor.normalize(duration, 'duration')
        
        processed_results.append({
            "original": sample,
            "extracted_features": {
                "duration_sec": duration,
                "normalized_duration": norm_dur,
                "protocol_vector": protocol_vec, # [TCP, UDP, ICMP]
                "ip_pattern_vector": ip_vec # [Internal, SameSubnet]
            }
        })
        
    return {"status": "success", "data": processed_results}