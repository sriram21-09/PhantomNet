from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import time
from backend.ml.preprocessing import DataPreprocessor

router = APIRouter()
preprocessor = DataPreprocessor()

class LogEvent(BaseModel):
    timestamp: str
    attacker_ip: str
    service_type: str = "UNKNOWN"
    packet_count: int = 0
    payload_size: int = 0
    payload: str = ""
    status: str = "Unknown"
    class Config:
        extra = "allow"

@router.get("/features/{event_id}")
def get_single_feature(event_id: str):
    return {"event_id": event_id, "status": "Not implemented (DB lookup required)"}

@router.post("/features/batch")
def extract_features_batch(logs: List[Dict[str, Any]]):
    start_time = time.time()
    try:
        # Preprocess (Scale & Extract)
        features_matrix = preprocessor.process_and_label(logs)
        
        # Convert numpy array to list for JSON response
        response_data = features_matrix.tolist()
        
        duration = (time.time() - start_time) * 1000 # ms
        
        return {
            "batch_size": len(logs),
            "processing_time_ms": round(duration, 2),
            "features": response_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))