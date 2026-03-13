# ML Inference Service — API Specification

**Project:** PhantomNet  
**Version:** v1.0.0-draft  
**Date:** March 11, 2026  
**Base URL:** `/api/v2/inference`

---

## Overview

The ML Inference Service exposes a REST API for real-time threat classification using trained ML models managed by the `ModelRegistry`. It is built on **FastAPI** for async performance and supports JSON request/response payloads.

---

## Authentication

All inference endpoints require a valid API key passed in the `X-API-Key` header.

```
X-API-Key: <your-api-key>
```

---

## Endpoints

### 1. `POST /api/v2/inference/predict`

Submits a network event (or batch of events) for threat classification.

**Request Body:**
```json
{
  "events": [
    {
      "source_ip": "192.168.1.105",
      "destination_port": 22,
      "protocol": "SSH",
      "payload_size": 1024,
      "timestamp": "2026-03-11T10:00:00Z",
      "features": {
        "packet_rate": 150.5,
        "byte_rate": 8192.0,
        "connection_duration": 3.2,
        "failed_login_attempts": 5,
        "unique_commands": 12
      }
    }
  ],
  "model_version": "latest"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `events` | Array | ✅ | List of network event objects to classify |
| `events[].source_ip` | String | ✅ | Source IP address |
| `events[].destination_port` | Integer | ✅ | Target port |
| `events[].protocol` | String | ✅ | Protocol type (SSH, HTTP, FTP, SMTP) |
| `events[].payload_size` | Integer | ✅ | Payload size in bytes |
| `events[].timestamp` | String (ISO 8601) | ✅ | Event timestamp |
| `events[].features` | Object | ✅ | Extracted features matching the training schema |
| `model_version` | String | ❌ | Specific model version or `"latest"` (default) |

**Response (`200 OK`):**
```json
{
  "predictions": [
    {
      "event_index": 0,
      "classification": "malicious",
      "confidence": 0.94,
      "threat_type": "brute_force",
      "model_version": "v1.2.0",
      "inference_time_ms": 12.4
    }
  ],
  "metadata": {
    "model_version": "v1.2.0",
    "total_events": 1,
    "total_inference_time_ms": 12.4
  }
}
```

| Field | Type | Description |
|---|---|---|
| `predictions[].classification` | String | `"benign"` or `"malicious"` |
| `predictions[].confidence` | Float | Confidence score (0.0–1.0) |
| `predictions[].threat_type` | String | Threat category (e.g., `brute_force`, `port_scan`, `data_exfiltration`, `benign`) |
| `predictions[].model_version` | String | Model version used for this prediction |
| `predictions[].inference_time_ms` | Float | Time taken for this single inference |

---

### 2. `GET /api/v2/inference/models`

Returns all registered models and their metadata from the `ModelRegistry`.

**Response (`200 OK`):**
```json
{
  "models": [
    {
      "version": "v1.2.0",
      "name": "IsolationForest_Anomaly",
      "status": "Production",
      "training_date": "2026-03-10T14:30:00",
      "metrics": {
        "accuracy": 0.91,
        "f1_score": 0.89,
        "precision": 0.88,
        "recall": 0.93
      }
    }
  ]
}
```

---

### 3. `GET /api/v2/inference/models/{version}`

Returns metadata for a specific model version.

**Path Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `version` | String | Model version (e.g., `v1.2.0`) |

**Response (`200 OK`):**
```json
{
  "version": "v1.2.0",
  "name": "IsolationForest_Anomaly",
  "status": "Production",
  "training_date": "2026-03-10T14:30:00",
  "path": "ml_models/registry/IsolationForest_Anomaly_v1.2.0.pkl",
  "metrics": { "accuracy": 0.91, "f1_score": 0.89 },
  "features": ["packet_rate", "byte_rate", "connection_duration", "failed_login_attempts"],
  "hyperparameters": { "n_estimators": 200, "contamination": 0.05 }
}
```

**Response (`404 Not Found`):**
```json
{
  "error": "Model version v9.9.9 not found in registry."
}
```

---

### 4. `POST /api/v2/inference/models/{version}/promote`

Promotes a model to `Production` status (archives the current production model).

**Path Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `version` | String | Model version to promote |

**Response (`200 OK`):**
```json
{
  "message": "Model v1.2.0 promoted to Production.",
  "previous_production": "v1.1.0"
}
```

---

### 5. `POST /api/v2/inference/models/{version}/rollback`

Rolls back a model by archiving it and restoring the previous production version.

**Response (`200 OK`):**
```json
{
  "message": "Model v1.2.0 rolled back. Restored v1.1.0 to Production.",
  "rolled_back_version": "v1.2.0",
  "restored_version": "v1.1.0"
}
```

---

### 6. `GET /api/v2/inference/health`

Health check endpoint for monitoring and load balancers.

**Response (`200 OK`):**
```json
{
  "status": "healthy",
  "active_model": "v1.2.0",
  "uptime_seconds": 86400,
  "last_inference_at": "2026-03-11T10:15:00Z"
}
```

---

## Error Responses

All error responses follow a consistent format:

```json
{
  "error": "Human-readable error message",
  "code": "ERROR_CODE",
  "details": {}
}
```

| HTTP Code | Error Code | Description |
|---|---|---|
| `400` | `INVALID_REQUEST` | Missing or malformed fields in request body |
| `401` | `UNAUTHORIZED` | Missing or invalid API key |
| `404` | `MODEL_NOT_FOUND` | Requested model version does not exist |
| `422` | `FEATURE_MISMATCH` | Event features don't match model's expected schema |
| `500` | `INFERENCE_ERROR` | Internal model inference failure |
| `503` | `SERVICE_UNAVAILABLE` | No production model loaded |

---

## Rate Limiting

| Tier | Requests/min | Burst |
|---|---|---|
| Standard | 60 | 100 |
| Premium | 300 | 500 |

Rate limit headers are included in every response:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 58
X-RateLimit-Reset: 1710150000
```
