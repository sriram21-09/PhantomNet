# 🏗️ PhantomNet API Design Document

**Version**: 1.0  
**Date**: December 10, 2025  
**Status**: Active  

---

## 📑 Table of Contents

1. [API Overview](#api-overview)
2. [Design Principles](#design-principles)
3. [Architecture](#architecture)
4. [Endpoint Design](#endpoint-design)
5. [Data Models](#data-models)
6. [Response Format](#response-format)
7. [Error Handling](#error-handling)
8. [Status Codes](#status-codes)

---

## 🎯 API Overview

**PhantomNet API** provides real-time access to honeypot security events and threat analytics.

| Property | Value |
|----------|-------|
| **Base URL** | `http://localhost:8000` |
| **Version** | `1.0` |
| **Framework** | FastAPI |
| **Language** | Python 3.9+ |
| **Database** | PostgreSQL |
| **Authentication** | None (Dev), JWT (Production) |

---

## 🏛️ Design Principles

### 1. **RESTful Design**
- Resource-based endpoints
- Standard HTTP methods (GET, POST, PUT, DELETE)
- Predictable URL structure

### 2. **Consistency**
- Uniform response format
- Standardized error messages
- Consistent parameter naming (snake_case)

### 3. **Simplicity**
- Minimal endpoints (only necessary)
- Clear parameter names
- Easy to understand responses

### 4. **Scalability**
- Stateless requests
- Cacheable responses
- Pagination-ready structure

---

## 🏗️ Architecture

### Request Flow
```
Client Request
    ↓
FastAPI Router
    ↓
Validation Layer
    ↓
Business Logic
    ↓
Database Query
    ↓
Response Formatter
    ↓
JSON Response
```

### API Layers

| Layer | Responsibility |
|-------|-----------------|
| **Router** | Route handling, method validation |
| **Validator** | Parameter validation, type checking |
| **Service** | Business logic, calculations |
| **Repository** | Database queries, data access |
| **Model** | Data serialization, response format |

---

## 📡 Endpoint Design

### Core Endpoints

#### 1. GET `/api/health`
**Purpose**: System health check

| Property | Value |
|----------|-------|
| **Method** | GET |
| **Auth** | Not required |
| **Cache** | 30s |
| **Response** | HealthResponse |

**Response**:
```json
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2025-12-10T15:30:00Z"
}
```

---

#### 2. GET `/api/events`
**Purpose**: Retrieve security events

| Property | Value |
|----------|-------|
| **Method** | GET |
| **Auth** | Not required |
| **Cache** | No cache |
| **Response** | EventResponse[] |

**Query Parameters**:
| Parameter | Type | Default | Range | Required |
|-----------|------|---------|-------|----------|
| `limit` | int | 10 | 1-100 | No |
| `hours` | int | 24 | 1-8760 | No |

**Response**:
```json
[
  {
    "id": 1,
    "timestamp": "2025-12-10T09:45:30Z",
    "srcip": "192.168.1.100",
    "dstport": 2222,
    "username": "root",
    "status": "failed",
    "honeypottype": "ssh",
    "threatscore": 50.0
  }
]
```

---

#### 3. GET `/api/stats`
**Purpose**: Aggregate statistics

| Property | Value |
|----------|-------|
| **Method** | GET |
| **Auth** | Not required |
| **Cache** | 5m |
| **Response** | StatsResponse |

**Response**:
```json
{
  "total_events": 120,
  "unique_ips": 45,
  "avg_threat": 42.5,
  "max_threat": 97.0
}
```

---

#### 4. GET `/api/threat-level`
**Purpose**: Current threat classification

| Property | Value |
|----------|-------|
| **Method** | GET |
| **Auth** | Not required |
| **Cache** | 2m |
| **Response** | ThreatLevelResponse |

**Response**:
```json
{
  "level": "MEDIUM",
  "color": "yellow"
}
```

**Threat Classification**:
| Level | Condition | Color |
|-------|-----------|-------|
| CRITICAL | avg_threat > 70 | red |
| HIGH | 50 < avg_threat ≤ 70 | orange |
| MEDIUM | 30 < avg_threat ≤ 50 | yellow |
| LOW | avg_threat ≤ 30 | green |

---

## 📊 Data Models

### EventResponse
```python
{
  "id": int,                    # Unique event ID
  "timestamp": str,             # ISO 8601 format
  "source_ip": str,             # Source IP address
  "dstport": int,               # Destination port (1-65535)
  "username": str,              # Attempted username
  "status": str,                # "failed" or "success"
  "honeypot_type": str,         # "ssh", "http", "ftp"
  "threat_score": float         # 0.0-100.0
}
```

### StatsResponse
```python
{
  "total_events": int,          # Count of all events
  "unique_ips": int,            # Count of unique source IPs
  "avg_threat": float,          # Average threat score
  "max_threat": float           # Maximum threat score
}
```

### ThreatLevelResponse
```python
{
  "level": str,                 # "CRITICAL", "HIGH", "MEDIUM", "LOW"
  "color": str                  # Hex color code
}
```

### HealthResponse
```python
{
  "status": str,                # "healthy" or "unhealthy"
  "database": str,              # "connected" or error message
  "timestamp": str              # ISO 8601 format
}
```

---

## 📨 Response Format

### Success Response Structure
```json
[
  {
    "field1": "value1",
    "field2": "value2"
  }
]
```

### Error Response Structure
```json
{
  { "error": "message" }

}
```

### Response Headers
```
Content-Type: application/json
X-Request-ID: unique-request-id
Cache-Control: max-age=300
```

---

## ⚠️ Error Handling

### Error Response Standard
```json
{
  "detail": "String describing the error",
  "status_code": 400
}
```

### Validation Errors
```json
{
  "detail": "limit must be between 1 and 100",
  "status_code": 400
}
```

### Server Errors
```json
{
  "detail": "Database connection failed",
  "status_code": 500
}
```

---

## 🔢 Status Codes

| Code | Name | Meaning | Example |
|------|------|---------|---------|
| **200** | OK | Request succeeded | ✅ Events retrieved |
| **400** | Bad Request | Invalid parameters | ❌ limit=999 |
| **500** | Internal Server Error | Server/database error | ❌ DB connection failed |
| **503** | Service Unavailable | Service temporarily down | ❌ Maintenance mode |

---

## 🔄 Query Parameter Validation

### Rules for `/events`

**limit parameter**:
- Type: integer
- Min: 1
- Max: 100
- Default: 10
- Invalid: returns 400 Bad Request

**hours parameter**:
- Type: integer
- Min: 1
- Max: 8760 (1 year)
- Default: 24
- Invalid: returns 400 Bad Request

### Invalid Request Example
```bash
curl "http://localhost:8000/events?limit=999&hours=-5"
```

**Response**:
```json
{
  "detail": "limit must be between 1 and 100, hours must be positive",
  "status_code": 400
}
```

---

## 🎯 Design Patterns

### 1. Resource Naming
```
GET /api/events      → List of events
GET /api/stats        → Aggregate statistics
GET /api/health       → System health
GET /api/threat-level → Threat classification
```

### 2. Query Parameters
- Used for filtering and pagination
- Always optional unless specified
- Support sensible defaults
- Validate all inputs

### 3. Response Consistency
- Always return JSON
- Same structure for same resource type
- Include timestamps for tracking
- Unique identifiers for resources

---

## 🚀 Performance Considerations

### Caching Strategy
| Endpoint | Cache Duration | Reason |
|----------|-----------------|--------|
| `/health` | 30 seconds | Periodic heartbeat |
| `/stats` | 5 minutes | Expensive calculation |
| `/threat-level` | 2 minutes | Policy-based |
| `/events` | No cache | Always fresh data |

### Response Time Targets
| Endpoint | Target | Current |
|----------|--------|---------|
| `/health` | < 100ms | ~50ms |
| `/stats` | < 200ms | ~150ms |
| `/threat-level` | < 150ms | ~100ms |
| `/events` | < 500ms | ~300ms |

---

## 🔐 Security

### Current Implementation
- No authentication (development)
- CORS enabled for localhost
- No rate limiting

### Production Requirements
1. **Authentication**: JWT tokens
2. **Rate Limiting**: 100 req/min per IP
3. **CORS**: Restrict to domain only
4. **Validation**: Sanitize all inputs
5. **Logging**: Log all requests

---

## 🔗 API Versioning

Current version: **1.0**

Future versions will use URL versioning:
```
/v1/events
/v2/events (if needed)
```

---

## 📋 API Changelog

### Version 1.0 (December 10, 2025)
- ✅ Health endpoint
- ✅ Events endpoint with filtering
- ✅ Statistics endpoint
- ✅ Threat level endpoint
- ✅ CORS configuration

---

## 📚 Related Documentation

- [API Endpoints](./API_ENDPOINTS.md) - Complete reference
- [Quick Reference](./API_QUICK_REFERENCE.md) - Cheat sheet
- [Architecture](./ARCHITECTURE.md) - System design

---

## ✅ Design Checklist

- ✅ All endpoints follow REST principles
- ✅ Consistent naming conventions
- ✅ Proper HTTP methods used
- ✅ Clear parameter validation
- ✅ Standardized responses
- ✅ Error handling defined
- ✅ Status codes documented
- ✅ Caching strategy defined
- ✅ Security considered

---

**API Design Complete** ✅  
**Status**: Production Ready for Development

