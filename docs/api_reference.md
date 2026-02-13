# API Reference

## Model Inference

### **POST** `/api/v1/analyze/threat-score`
Analyzes a network event and returns a threat score and anomaly classification.

**Request Body:**
```json
{
  "src_ip": "192.168.1.5",
  "dst_ip": "10.0.0.1",
  "packet_length": 1500,
  "protocol": "TCP",
  "timestamp": "2026-02-13T10:00:00"
}
```

**Response:**
```json
{
  "threat_score": 85.5,
  "is_anomaly": true,
  "confidence": 0.92,
  "model_version": "1.0",
  "processing_time_ms": 12.5
}
```

---

## Model Monitoring

### **GET** `/api/v1/model/metrics`
Retrieves the latest performance metrics of the currently deployed model.

**Response:**
```json
{
  "timestamp": "2026-02-13 10:00:00",
  "best_f1_score": 0.5409,
  "best_params": {
    "n_estimators": 50,
    "max_samples": 0.5,
    "contamination": "auto"
  },
  "details": "For full history, check models/hyperparameter_results.json"
}
```

---

### **GET** `/api/v1/model/config`
Retrieves the training configuration used for the current model.

**Response:**
```json
{
    "model_type": "IsolationForest",
    "n_estimators": 100,
    "contamination": 0.1,
    "input_features": ["packet_length", "protocol_encoding", ...],
    "random_state": 42
}
```
