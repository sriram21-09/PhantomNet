# ML Data API Specification

**Project:** PhantomNet  
**Version:** v1.0.0  
**Status:** Draft / Preparation for Month 4  
**Base URL:** `/api/v1/ml`

---

## Overview
This document specifies the Data API used by the ML Insights Dashboard to visualize model performance, feature impact, and prediction distributions.

---

## Endpoints

### 1. `GET /api/v1/ml/stats`
Returns the latest aggregated performance metrics for the active production model.

**Response (`200 OK`):**
```json
{
  "version": "v3.0.0",
  "name": "AttackClassifier_Enhanced",
  "metrics": {
    "accuracy": 0.942,
    "f1_score": 0.931,
    "precision": 0.925,
    "recall": 0.938,
    "auc": 0.975
  },
  "last_updated": "2026-03-13T10:00:00Z"
}
```

---

### 2. `GET /api/v1/ml/feature-importance`
Returns the top features contributing to the model's classification decisions.

**Response (`200 OK`):**
```json
{
  "features": [
    { "name": "Packet Size Variance", "importance": 0.85 },
    { "name": "Connection Duration", "importance": 0.72 },
    { "name": "Payload Entropy", "importance": 0.64 },
    { "name": "Source Port Frequency", "importance": 0.45 },
    { "name": "TCP Flags Count", "importance": 0.38 }
  ]
}
```

---

### 3. `GET /api/v1/ml/predictions/recent`
Returns the distribution of predictions (Benign vs Malicious) over the last period, used for the Area Chart.

**Response (`200 OK`):**
```json
{
  "data": [
    { "time": "10:00", "benign": 400, "malicious": 240 },
    { "time": "11:00", "benign": 300, "malicious": 139 },
    { "time": "12:00", "benign": 200, "malicious": 980 },
    { "time": "13:00", "benign": 278, "malicious": 390 },
    { "time": "14:00", "benign": 189, "malicious": 480 }
  ]
}
```

---

### 4. `GET /api/v1/ml/confidence-histogram`
Returns data for the confidence distribution histogram.

**Response (`200 OK`):**
```json
{
  "buckets": [
    { "range": "0.0-0.2", "count": 50 },
    { "range": "0.2-0.4", "count": 80 },
    { "range": "0.4-0.6", "count": 150 },
    { "range": "0.6-0.8", "count": 450 },
    { "range": "0.8-1.0", "count": 1200 }
  ]
}
```

---

## Error Handling
Standard HTTP status codes apply:
- `200 OK`: Success
- `404 Not Found`: Data or model not available
- `500 Internal Server Error`: Generic server error
