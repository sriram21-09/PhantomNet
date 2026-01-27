# PhantomNet — API Specification (Final)

**Project:** PhantomNet  
**Phase:** Month 1 (Post Week 5 Stabilization)  
**Environment:** Local / Lab  
**Status:** Active  
**Audience:** Backend, ML, Frontend (future)  

---

## Base URL
```
http://localhost:8000
```

> Note: The `/api` prefix is used only for specific endpoints (stats, events, ML).

---

## Authentication
- No authentication in Phase 1  
- All endpoints are public for controlled lab usage  
- Network access is restricted at the infrastructure level  
- Authentication and RBAC are planned for later phases  

---

## Global Error Format
All API errors follow this structure:

```json
{
  "detail": "error message"
}
```

---

## 1. Root Status
**GET /**

Confirms that the PhantomNet backend is running.

**Response — 200 OK**
```json
{
  "message": "PhantomNet Active Defense System: ONLINE"
}
```

---

## 2. Health Check
**GET /health**

Service and database liveness probe.

**Response — 200 OK**
```json
{
  "status": "healthy",
  "database": "connected"
}
```

**Failure Response**
```json
{
  "status": "error",
  "database": "<error message>"
}
```

---

## 3. Live Traffic Analysis
**GET /analyze-traffic**

Returns recent packet-level traffic enriched with AI-based analysis.  
Used by the dashboard live feed.  

**Data Source:** `packet_logs`

**Response — 200 OK**
```json
{
  "status": "success",
  "count": 50,
  "data": [
    {
      "packet_info": {
        "src": "192.168.1.10",
        "dst": "192.168.1.52",
        "proto": "TCP",
        "length": 64,
        "location": "IN"
      },
      "ai_analysis": {
        "prediction": "SUSPICIOUS",
        "threat_score": 0.62,
        "confidence_percent": "62%"
      }
    }
  ]
}
```

**Notes**
- Geo lookup failures are safely handled  
- No mock data is returned  
- All values are backend-derived  

---

## 4. Dashboard Statistics
**GET /api/stats**

Returns aggregated statistics for dashboard summary cards.  
Backed by the `traffic_stats` cache table.

**Response — 200 OK**
```json
{
  "totalEvents": 1840,
  "uniqueIPs": 7,
  "activeHoneypots": 1,
  "avgThreatScore": 0,
  "criticalAlerts": 0
}
```

**Field Definitions**

| Field           | Description                          |
|-----------------|--------------------------------------|
| totalEvents     | Total suspicious or malicious events |
| uniqueIPs       | Unique attacker IP count             |
| activeHoneypots | Active honeypot types                |
| avgThreatScore  | Reserved for future use              |
| criticalAlerts  | High-severity alerts (future)        |

---

## 5. Security Events API
**GET /api/events**

Primary SOC-style events endpoint.  
This is the single source of truth for the Events page.  

**Data Source:** `packet_logs`

**Query Parameters**

| Parameter | Type    | Description                       |
|-----------|---------|-----------------------------------|
| threat    | string  | BENIGN / SUSPICIOUS / MALICIOUS   |
| protocol  | string  | TCP / UDP / ICMP                  |
| limit     | integer | Max number of events (default: 100)|

**Response — 200 OK**
```json
[
  {
    "time": "2026-01-05 14:12:33",
    "ip": "192.168.1.10",
    "type": "TCP",
    "port": 0,
    "threat": "SUSPICIOUS",
    "details": "Suspicious TCP traffic detected"
  }
]
```

**Notes**
- Threat classification is performed only in the backend  
- Frontend does not recalculate threat levels  
- Fully database-backed (no mock data)  

---

## 6. Active Defense — Block IP
**POST /active-defense/block/{ip}**

Blocks an IP address via the firewall service.

**Path Parameter**
- `ip` — IPv4 address to block  

**Success Response**
```json
{
  "status": "success",
  "message": "IP blocked successfully"
}
```

**Error Response**
```json
{
  "status": "error",
  "message": "Cannot block localhost"
}
```

**Constraints**
- Localhost (`127.0.0.1`, `localhost`, `::1`) is protected  
- Blocking logic is enforced at backend and firewall layers  

---

## 7. ML Feature Extraction APIs (Week 6)

These endpoints expose derived ML features only.  
They do not modify database state.  

**Base Path:** `/api/ml`  

**Primary Data Source:** `packet_logs`  
**Enrichment Tables:** `ssh_logs`, `http_logs`, `ftp_logs`, `asyncssh_logs`  

---

### 7.1 Get Features for Single Event
**GET /api/ml/features/{event_id}**

Returns the complete ML feature vector for a single event.

**Path Parameters**
- `event_id` (integer) — ID from `packet_logs`

**Response — 200 OK**
```json
{
  "event_id": 12345,
  "features": {
    "packet_length": 512,
    "protocol_encoding": 1,
    "source_ip_event_rate": 8.3,
    "destination_port_class": "well_known",
    "threat_score": 72.4,
    "malicious_flag_ratio": 0.6,
    "attack_type_frequency": 4,
    "time_of_day_deviation": true,
    "burst_rate": 12.1,
    "packet_size_variance": 220.5,
    "honeypot_interaction_count": 2,
    "session_duration_estimate": 480,
    "unique_destination_count": 6,
    "rolling_average_deviation": 1.9,
    "z_score_anomaly": 2.6
  }
}
```

**Error Responses**
- 404 — Event not found  
- 422 — Feature computation error  
- 500 — Internal server error  

---

### 7.2 Batch Feature Extraction
**POST /api/ml/features/batch**

Returns ML feature vectors for multiple events.

**Request Body**
```json
{
  "event_ids": [101, 102, 103]
}
```

**Response — 200 OK**
```json
{
  "results": [
    {
      "event_id": 101,
      "features": { "...": "..." }
    },
    {
      "event_id": 102,
      "features": { "...": "..." }
    }
  ]
}
```

**Error Responses**
- 400 — Invalid request format  
- 413 — Too many event IDs requested  
- 422 — Partial feature computation failure  
- 500 — Internal server error  

---

## ML API Design Constraints
- All ML APIs are **READ-ONLY**  
- No database mutations are permitted  
- Feature computation must be deterministic  
- No schema changes allowed  
- `packet_logs` remains the single source of truth  
---
