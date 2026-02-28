# PhantomNet — Performance Tuning Guide

**Week 9 | Day 4 — Performance Optimization & Monitoring**  
**Last Updated:** February 27, 2026

---

## Overview

PhantomNet implements three layers of performance optimization:

```
Request → MetricsMiddleware → ProfilingMiddleware → CORS → FastAPI App
                │                     │
           Prometheus            X-Process-Time
           /metrics              X-Memory-Delta
                                 Slow query logs
                                      │
                                 TTL Cache
                              (api_cache decorator)
                                      │
                              Database (Indexed)
```

---

## 1. SQL Index Optimization

### Indexed Columns

| Table | Column | Index Added | Rationale |
|-------|--------|-------------|-----------|
| `packet_logs` | `timestamp` | ✅ | ORDER BY in every query |
| `packet_logs` | `src_ip` | ✅ (existing) | WHERE filter, GROUP BY |
| `packet_logs` | `protocol` | ✅ | WHERE filter in events API |
| `packet_logs` | `threat_score` | ✅ | WHERE ≥ 0.8 for critical alerts |
| `packet_logs` | `threat_level` | ✅ | WHERE filter in events API |
| `events` | `source_ip` | ✅ | WHERE filter for geo enrichment |
| `events` | `timestamp` | ✅ | ORDER BY |

### Verifying Indexes

```sql
-- Check existing indexes
SELECT indexname, tablename
FROM pg_indexes
WHERE tablename IN ('packet_logs', 'events');

-- EXPLAIN a query to verify index usage
EXPLAIN ANALYZE
SELECT * FROM packet_logs
WHERE protocol = 'SSH'
ORDER BY timestamp DESC
LIMIT 50;
```

---

## 2. API Response Caching

### Configuration

| Endpoint | TTL | Rationale |
|----------|-----|-----------|
| `/api/stats` | 15s | Dashboard stats don't need real-time refresh |
| Custom endpoints | Configurable | Use `@cache_response(ttl_seconds=N)` |

### Usage

```python
from middleware.cache import cache_response, invalidate_cache

@app.get("/api/stats")
@cache_response(ttl_seconds=15)
def get_stats(db = Depends(get_db)):
    ...

# Manual invalidation
invalidate_cache("get_stats")
```

### Monitoring

```
GET /api/cache/stats
```

```json
{
  "size": 12,
  "max_size": 500,
  "hits": 145,
  "misses": 23,
  "hit_rate": 86.3,
  "default_ttl": 30
}
```

---

## 3. Request Profiling

### Response Headers

Every API response includes:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Process-Time` | Request duration | `12.45ms` |
| `X-Memory-Delta` | Memory change (if enabled) | `24.5KB` |

### Slow Request Logging

Requests exceeding 500ms are logged as warnings:

```
[SLOW] GET /api/analytics/attack-map took 650ms (threshold: 500ms)
```

### Enabling Memory Tracking

In `main.py`, set `enable_memory_tracking=True`:

```python
app.add_middleware(ProfilingMiddleware, enable_memory_tracking=True)
```

> **Note:** Memory tracking adds ~2ms overhead per request via `tracemalloc`.

---

## 4. Prometheus Metrics

### Endpoint

```
GET /metrics
```

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `phantomnet_requests_total` | Counter | method, path, status | Total HTTP requests |
| `phantomnet_errors_total` | Counter | method, path | 4xx/5xx errors |
| `phantomnet_request_duration_ms` | Histogram | method, path | Response time (ms) |
| `phantomnet_active_connections` | Gauge | — | Current connections |

### Histogram Buckets

Duration: `5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000` ms

### Sample Output

```
# HELP phantomnet_requests_total Total HTTP requests
# TYPE phantomnet_requests_total counter
phantomnet_requests_total{method="GET",path="/api/stats",status="200"} 42
phantomnet_requests_total{method="GET",path="/api/events",status="200"} 15

# HELP phantomnet_request_duration_ms Request duration in milliseconds
# TYPE phantomnet_request_duration_ms histogram
phantomnet_request_duration_ms_bucket{method="GET",path="/api/stats",le="50"} 40
phantomnet_request_duration_ms_bucket{method="GET",path="/api/stats",le="100"} 42
```

### Prometheus Scrape Config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'phantomnet'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8000']
```

---

## Files

| File | Type | Purpose |
|------|------|---------|
| `backend/middleware/cache.py` | NEW | TTL response cache with decorator |
| `backend/middleware/profiling.py` | NEW | Request timing + memory profiling |
| `backend/middleware/metrics_collector.py` | NEW | Prometheus metrics exporter |
| `backend/database/models.py` | MODIFIED | SQL indexes on 6 columns |
| `backend/main.py` | MODIFIED | Middleware registration + endpoints |
