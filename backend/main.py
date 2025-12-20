from fastapi import FastAPI
from services.feature_extractor import FeatureExtractor
from services.ai_predictor import ThreatDetector
import pandas as pd
import numpy as np

app = FastAPI()

# Initialize Services
extractor = FeatureExtractor()
detector = ThreatDetector()

@app.get("/")
def read_root():
    return {"message": "PhantomNet Backend is Running"}

@app.get("/analyze-traffic")
def analyze_traffic():
    """
    Full Pipeline: Generate -> Extract -> AI Predict -> Result
    """
    # 1. Generate Dummy Data
    raw_samples = extractor.generate_labeled_sample()
    results = []
    
    for sample in raw_samples:
        # 2. Extract Features
        duration = extractor.extract_time_features(sample['start'], sample['end'])
        norm_dur = extractor.normalize(duration, 'duration')
        proto_vec = extractor.encode_protocol(sample['proto'])
        ip_vec = extractor.extract_ip_patterns(sample['src'], sample['dst'])
        
        # 3. Create Feature Vector (Must match training order!)
        # [Duration, Internal, SameSubnet, TCP, UDP, ICMP]
        features = [norm_dur, ip_vec[0], ip_vec[1]] + proto_vec
        
        # 4. AI Prediction (Get Threat Score)
        pred_label, threat_score = detector.predict(features)
        
        results.append({
            "packet_info": sample,
            "ai_analysis": {
                "prediction": pred_label,
                "threat_score": threat_score, # e.g. 0.95
                "confidence_percent": f"{threat_score*100:.1f}%"
            }
        })
        
    return {"status": "success", "data": results}