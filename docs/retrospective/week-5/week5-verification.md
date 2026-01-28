# PhantomNet — Week 5 Verification Summary (Facts Only)

**Purpose:**  
This document captures *verified, evidence-backed facts* from Week 5.  
It serves as the factual input for:
- Week 5 Retrospective
- Metrics Review
- Week 6 Planning

> ⚠️ This file intentionally contains **no opinions, conclusions, or plans**.

---

## 1. Backend Verification

### Status
- FastAPI backend runs stably without crashes
- Uvicorn reload works as expected
- Background sniffer starts automatically on application startup

### Verified Capabilities
- Real-time packet sniffing active
- Continuous packet ingestion into PostgreSQL
- Stats aggregation runs on live data
- Events API returns database-backed results
- Honeypot status API responds successfully

### Evidence
- Repeated log entries:
[SUSPICIOUS] <src_ip> -> <dst_ip> | Score: <value> (Saved to DB)

yaml
Copy code
- Successful responses:
- `GET /api/stats` → 200 OK
- `GET /api/events` → 200 OK
- `GET /api/honeypots/status` → 200 OK

---

## 2. Database Verification

### Database
- PostgreSQL used as primary datastore
- Database connection stable under continuous writes

### Table: `packet_logs`
Verified schema (via `information_schema.columns`):

| Column Name   | Data Type                  |
|--------------|----------------------------|
| id           | integer                    |
| timestamp    | timestamp without time zone|
| src_ip       | character varying          |
| dst_ip       | character varying          |
| protocol     | character varying          |
| length       | integer                    |
| is_malicious | boolean                    |
| threat_score | double precision           |
| attack_type  | character varying          |

### Verified Behavior
- Schema matches SQLAlchemy ORM
- No missing or undefined columns
- Queries execute without runtime errors
- High-frequency inserts sustained

---

## 3. Frontend Verification

### Dashboard
- Displays real-time metrics from backend
- Metrics update dynamically without reload
- No mock data displayed during normal operation

### Events Page
- Shows live events from database
- Pagination and filtering functional
- Timestamps align with backend logs

### Honeypot Status
- Real-time data loaded from backend API
- No fallback to mock data observed
- Status updates consistently

### Evidence
- Realistic, changing values (not static)
- No "Backend unavailable" warnings
- API calls visible in browser network tab

---

## 4. Verified Metrics Snapshot (Observed)

| Metric              | Observed Value (Approx.) |
|---------------------|--------------------------|
| Total Events        | 368,000+                 |
| Unique IPs          | 730+                     |
| Active Honeypots    | 4                        |
| Avg Threat Score    | ~57%                     |
| Critical Alerts     | ~17,000                  |

> Note: Values continue to change as live traffic is ingested.

---

## 5. Verified Technical Decisions

The following decisions were implemented and confirmed to work:

- Removed undefined ORM fields instead of altering DB schema
- Standardized `packet_logs` as the single source of truth
- Centralized metric computation via `StatsService`
- Disabled frontend mock fallbacks during normal operation
- Enforced backend-first data authority

---

## 6. Issues Encountered and Resolved

| Issue | Status |
|-----|-------|
ORM–DB schema mismatch | Fixed |
CI dependency version mismatch | Fixed |
Stats API runtime failure | Fixed |
Frontend mock masking backend errors | Fixed |

---

## 7. Known Current Limitations (Accepted)

- No authentication or RBAC (by design)
- No automated integration tests yet
- Honeypot health inferred from activity, not heartbeats
- Alert severity thresholds not finalized

---
