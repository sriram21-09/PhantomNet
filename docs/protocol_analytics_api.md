# Protocol Analytics API

## Overview
The Protocol Analytics API provides insights into network traffic patterns, identifying potential threats like brute-force attempts and port scanning, and offering time-series data for visualization.

## Endpoints

### 1. SSH Analytics
**GET** `/api/v1/analytics/ssh`

Returns statistics specific to SSH traffic.

**Response:**
```json
{
  "protocol": "SSH",
  "total_events": 1500,
  "top_attackers": [
    {"ip": "192.168.1.5", "count": 450},
    {"ip": "10.0.0.12", "count": 120}
  ],
  "brute_force_suspects": [
    {"src_ip": "192.168.1.5", "count": 55}
  ]
}
```

### 2. HTTP Analytics
**GET** `/api/v1/analytics/http`

Returns statistics specific to HTTP traffic.

**Response:**
```json
{
  "protocol": "HTTP",
  "total_requests": 3200,
  "top_ips": [
    {"ip": "192.168.1.50", "count": 800}
  ],
  "potential_flooders": []
}
```

### 3. Global Attack Trends
**GET** `/api/v1/analytics/trends`

Returns daily attack volume for the last N days (default: 7).

**Parameters:**
- `days` (int, optional): Number of days to look back. Default: 7.

**Response:**
```json
[
  {"date": "2026-02-05", "count": 120},
  {"date": "2026-02-06", "count": 340},
  {"date": "2026-02-07", "count": 210}
]
```
