# Frontend ML Integration Guide

This document details the architecture and tasks for integrating the ML Insights Dashboard with the PhantomNet backend.

## Current Architecture (Month 3 Preparation)
The dashboard currently consumes data from a **Mock ML API** (Flask-based) to simulate the Month 4 production environment.

### Mock Server
- **Path**: `backend/mock_ml_api.py`
- **Address**: `http://localhost:5001`
- **Endpoints**:
    - `GET /api/v1/ml/stats`: Model performance summary.
    - `GET /api/v1/ml/feature-importance`: Global feature impact data.
    - `GET /api/v1/ml/predictions/recent`: Time-series prediction volume.
    - `GET /api/v1/ml/confidence-histogram`: Model confidence distribution.

## Integration Steps for Month 4

### 1. Transition to Production API
- Switch the `baseUrl` in `ModelMetricsDashboard.jsx` from `http://localhost:5001` to the production FastAPI endpoint (likely `http://localhost:8000/api/v1/ml`).
- Ensure the production API implements the same JSON schema as defined in `docs/ml_api_specification.md`.

### 2. Authentication Integration
- Add JWT or API Key headers to the `fetch` calls in the dashboard.
- Coordinate with the `AuthContext` to retrieve the current user's token.

### 3. WebSockets for Real-time (Optional Optimization)
- Consider replacing the 5-second polling interval with a WebSocket connection for lower latency and reduced server overhead.
- Frontend: Implement `socket.io-client` or native WebSockets in `useEffect`.
- Backend: Add a WebSocket handler in the ML API layer.

### 4. Dynamic Feature Extraction
- Update the Feature Importance query to support filtering by time range or specific traffic subsets.

## Verified Components
- [x] **ThreatScoreBadge**: Updated to respond to live metrics.
- [x] **FeatureImportanceChart**: Synchronized with API feature scores.
- [x] **ModelMetricsDashboard**: Centralized data fetching and polling implemented.
- [x] **Live/Idle Toggle**: Allows developers to pause polling during debugging.
