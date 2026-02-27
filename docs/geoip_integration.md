# PhantomNet — GeoIP Integration Guide

**Week 9 | Day 3 — GeoIP Lookup System**  
**Last Updated:** February 27, 2026

---

## Overview

PhantomNet uses IP geolocation to enrich attack events with geographic data (country, city, coordinates) for dashboard visualization and attack origin analysis.

**Architecture:**

```
Incoming Attack IP
       │
       ▼
┌─────────────────┐
│  GeoIPService    │
│  (Singleton)     │
├─────────────────┤
│ 1. Private IP?  │ → "LAN" (instant)
│ 2. Cached?      │ → Return cache (instant)
│ 3. MaxMind DB?  │ → GeoLite2-City.mmdb (fast, offline)
│ 4. Fallback     │ → ip-api.com (slow, online)
└────────┬────────┘
         ▼
  {country, city, lat, lon}
         │
    ┌────┴────┐
    ▼         ▼
 Database   API Response
 Enrichment  /attack-map
```

---

## Setup

### 1. Install Dependencies

```bash
pip install geoip2>=4.8.0 maxminddb>=2.6.0
```

### 2. MaxMind GeoLite2 Database (Optional)

1. Create a free account: [MaxMind Sign Up](https://www.maxmind.com/en/geolite2/signup)
2. Download **GeoLite2-City.mmdb** from your account dashboard
3. Place it at:

```
backend/data/GeoLite2-City.mmdb
```

Or set the environment variable:

```bash
export GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb
```

> **Note:** If the MaxMind database is not present, the service automatically falls back to ip-api.com (online, rate-limited to 45 req/min).

---

## API Endpoints

### Attack Map Data

```
GET /api/analytics/attack-map?limit=200
```

**Response:**

```json
{
  "status": "success",
  "total_events": 150,
  "total_locations": 12,
  "locations": [
    {
      "country": "China",
      "city": "Beijing",
      "lat": 39.9042,
      "lon": 116.4074,
      "flag": "🇨🇳",
      "count": 45,
      "protocols": ["SSH", "HTTP"],
      "avg_threat_score": 78.5
    }
  ],
  "top_countries": [
    {"country": "China", "count": 45},
    {"country": "Russia", "count": 32}
  ],
  "recent_attacks": [
    {
      "src_ip": "8.8.8.8",
      "protocol": "SSH",
      "threat_score": 85.0,
      "country": "United States",
      "lat": 37.386,
      "lon": -122.084,
      "timestamp": "2026-02-27T10:30:00"
    }
  ],
  "service_status": {
    "maxmind_available": true,
    "cache_size": 24
  }
}
```

### Single IP Lookup

```
GET /api/geoip/lookup/8.8.8.8
```

### Service Health

```
GET /api/geoip/status
```

---

## Database Schema Updates

### `packet_logs` table

| Column | Type | Description |
|--------|------|-------------|
| `country` | VARCHAR | Country name |
| `city` | VARCHAR | City name |
| `latitude` | FLOAT | GPS latitude |
| `longitude` | FLOAT | GPS longitude |

### `events` table (new columns)

| Column | Type | Description |
|--------|------|-------------|
| `country` | VARCHAR | Country name |
| `city` | VARCHAR | City name |
| `latitude` | FLOAT | GPS latitude |
| `longitude` | FLOAT | GPS longitude |

---

## Usage in Code

```python
from services.geoip_service import geoip_service

# Single lookup
geo = geoip_service.lookup("8.8.8.8")
print(geo)  # {'country': 'United States', 'city': 'Mountain View', ...}

# DB enrichment format
enrichment = geoip_service.enrich_record("8.8.8.8")
print(enrichment)  # {'country': ..., 'city': ..., 'latitude': ..., 'longitude': ...}

# Batch enrichment
results = geoip_service.batch_enrich(["8.8.8.8", "1.1.1.1"])
```

---

## Files Modified

| File | Change |
|------|--------|
| `backend/services/geoip_service.py` | **NEW** — MaxMind + fallback GeoIP service |
| `backend/database/models.py` | Added geo columns to `Event` table |
| `backend/app_models.py` | Added geo columns to `PacketLog` |
| `backend/main.py` | Added attack-map, lookup, and status endpoints |
| `requirements.txt` | Added `geoip2`, `maxminddb` |
