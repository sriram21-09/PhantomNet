
## 📡 All Endpoints at a Glance

| Endpoint | Method | Purpose | Parameters |
|----------|--------|---------|-----------|
| `/health` | GET | Check API & DB status | None |
| `/events` | GET | Get recent events | limit, hours |
| `/stats` | GET | Get aggregate stats | None |
| `/threat-level` | GET | Get current threat | None |

---

## 1️⃣ Health Check

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2025-12-10T09:45:30.123456"
}
```

---

## 2️⃣ Get Events

```bash
# Get last 10 events from past 24 hours
curl http://localhost:8000/events

# Get last 5 events from past 48 hours
curl "http://localhost:8000/events?limit=5&hours=48"

# Get all available events
curl "http://localhost:8000/events?limit=100&hours=168"
```

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2025-12-10T09:45:30",
    "srcip": "192.168.1.100",
    "dstport": 2222,
    "username": "root",
    "status": "failed",
    "honeypottype": "ssh",
    "threatscore": 50.0
  }
]
```

**Parameters:**
- `limit` (optional): 1-100, default 10
- `hours` (optional): positive int, default 24

---

## 3️⃣ Get Statistics

```bash
curl http://localhost:8000/stats
```

**Response:**
```json
{
  "total_events": 120,
  "unique_ips": 45,
  "avg_threat": 42.5,
  "max_threat": 97.0
}
```

---

## 4️⃣ Get Threat Level

```bash
curl http://localhost:8000/threat-level
```

**Response:**
```json
{
  "level": "MEDIUM",
  "color": "yellow"
}
```

**Threat Levels:**
| Level | Color | Avg Threat | Meaning |
|-------|-------|-----------|---------|
| CRITICAL | red | > 70 | Immediate action |
| HIGH | orange | 50-70 | Elevated threat |
| MEDIUM | yellow | 30-50 | Moderate threat |
| LOW | green | < 30 | Normal baseline |

---


## ✅ Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad request (invalid params) |
| 500 | Server/database error |

---

## 🧪 Test All 4 Endpoints

```bash
#!/bin/bash

echo "Testing all endpoints..."

echo "1. Health:"
curl -s http://localhost:8000/health | jq .

echo -e "\n2. Events:"
curl -s "http://localhost:8000/events?limit=3" | jq .

echo -e "\n3. Stats:"
curl -s http://localhost:8000/stats | jq .

echo -e "\n4. Threat Level:"
curl -s http://localhost:8000/threat-level | jq .

echo -e "\nAll tests done!"
```

---


## 🎯 TL;DR

```bash
# All 4 endpoints
curl http://localhost:8000/health
curl http://localhost:8000/events
curl http://localhost:8000/stats
curl http://localhost:8000/threat-level

# That's it! 🚀
```

