# PhantomNet – API Specification

**Project:** PhantomNet
**Phase:** Month 1 (Post Week 4 Stabilization)
**Environment:** Local / Lab
**Status:** Active

---

## Base URL

```
http://localhost:8000
```

> Note: The `/api` prefix is used only for specific endpoints (stats, events).

---

## Authentication

* No authentication in Phase 1
* All endpoints are public for controlled lab usage
* Network access is restricted at the infrastructure level
* Authentication and RBAC are planned for later phases

---

## 1. Root Status

### GET `/`

Confirms that the PhantomNet backend is running.

**Response — 200 OK**

```json
{
  "message": "PhantomNet Active Defense System: ONLINE"
}
```

---

## 2. Health Check

### GET `/health`

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

### GET `/analyze-traffic`

Returns recent packet-level traffic enriched with AI-based analysis.
Used by the dashboard live feed.

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

* Data source: `packet_logs`
* Geo lookup failures are safely handled
* No mock data is returned

---

## 4. Dashboard Statistics

### GET `/api/stats`

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
| --------------- | ------------------------------------ |
| totalEvents     | Total malicious or suspicious events |
| uniqueIPs       | Unique attacker IP count             |
| activeHoneypots | Active honeypot types                |
| avgThreatScore  | Reserved for future use              |
| criticalAlerts  | High-severity alerts (future)        |

---

## 5. Security Events API

### GET `/api/events`

Primary SOC-style events endpoint.
This is the single source of truth for the Events page.

**Query Parameters**

| Parameter | Type    | Description                           |
| --------- | ------- | ------------------------------------- |
| threat    | string  | BENIGN | SUSPICIOUS | MALICIOUS | ALL |
| protocol  | string  | TCP | UDP | ICMP | ALL                |
| limit     | integer | Max number of events (default: 100)   |

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

* Threat classification is performed only in the backend
* Frontend does not recalculate threat levels
* Fully database-backed (`packet_logs`)

---

## 6. Active Defense – Block IP

### POST `/active-defense/block/{ip}`

Blocks an IP address via the firewall service.

**Path Parameter**

| Name | Description           |
| ---- | --------------------- |
| ip   | IPv4 address to block |

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

* Localhost (`127.0.0.1`, `localhost`, `::1`) is protected

---

## Global Error Format

All API errors follow this structure:

```json
{
  "detail": "error message"
}
```

---

