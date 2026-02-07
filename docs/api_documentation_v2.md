# API Documentation – v2
## ML Prediction & Explainability Interface

---

## 1. Purpose

This document defines the stable API contract used by the frontend to consume
ML predictions and optional explainability metadata. It ensures consistent
integration and backward compatibility.

---

## 2. Prediction API Response

### Sample Response

```json
{
  "prediction": "Approved",
  "confidence": 0.87,
  "explainability": {
    "features": [
      { "name": "Credit Score", "contribution": 0.42 },
      { "name": "Income Level", "contribution": 0.31 },
      { "name": "Loan History", "contribution": 0.14 }
    ]
  }
}
