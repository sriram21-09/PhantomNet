# PhantomNet Production Baseline (v3.0.0-pre-hardening)

> **Generated**: 2026-09-18  
> **Git Reference**: Tag `v3.0.0-pre-hardening` on branch `fix/full-codebase-audit-remediation`  
> **Purpose**: Immutable reference point documenting system state, test results, schema definitions, and known vulnerabilities before hardening.

---

## 1. Test Suite Execution Baseline

Execution command: `pytest -q --tb=short` using Python 3.11.9 (`backend/venv`).

| Metric | Measured Value |
|---|---|
| **Total Test Items Collected** | **4,183** |
| **Unit Tests Passed** | **4,181** (100% of runnable unit tests) |
| **Tests Skipped** | **2** (`tests/integration/test_week10_integration.py`) |
| **Failed Tests** | **0** |
| **Subtests Passed** | **65** |
| **Total Execution Duration** | **241.25 seconds** (4 min 01 sec) |
| **Dedicated API Route Tests in `tests/api/`** | **0** (Entire API route surface untested prior to Phase 1) |

---

## 2. API Route Surface Inventory

Exported OpenAPI specification snapshot: [backend/openapi_baseline.json](file:///c:/Users/srira/Project/PhantomNet/backend/openapi_baseline.json).

| Category | Count | Route Paths | Current Auth State |
|---|---|---|:---:|
| **Authenticated Routers** | 3 | `/api/v1/admin/*`, `/api/v1/sentinel/*` (partial) | 🟢 Authenticated |
| **Unauthenticated Routers** | 13 | `/api/reports/*`, `/api/hunting/*`, `/api/cases/*`, `/api/alerts/*`, `/api/pcap/*`, `/api/topology/*`, `/api/honeypots/*`, `/api/management/*`, `/taxii2/*`, `/api/predictive/*`, `/api/attack_attribution/*`, `/api/metrics/*`, `/api/protocol_analytics/*` | 🔴 **UNPROTECTED** |
| **Active Defense Endpoints** | 3 | `/active-defense/block/{ip}`, `/api/response/policy`, `/api/response/unblock/{ip}` | 🔴 **UNPROTECTED** |
| **Total Exposed API Paths** | **104** | Comprehensive OpenAPI path list in `openapi_baseline.json` | 13% Auth / 87% Unauth |

---

## 3. Database Schema Baseline

Exported DDL schema definition: [backend/schema_baseline.sql](file:///c:/Users/srira/Project/PhantomNet/backend/schema_baseline.sql).

Total Registered Tables: **17**

| # | Table Name | Key Purpose | Primary Key | Critical Indexes |
|---|---|---|---|---|
| 1 | `alerts` | Threat alerts from baseline/correlation | `id` (INTEGER) | `timestamp`, `level`, `type`, `source_ip` |
| 2 | `attack_sessions` | Session clustering for attacks | `id` (INTEGER) | `attacker_ip` |
| 3 | `investigation_cases` | Security analyst incident cases | `id` (INTEGER) | `title` |
| 4 | `iocs` | Indicators of Compromise | `id` (INTEGER) | `type`, `value` |
| 5 | `packet_logs` | Raw sniffer packet telemetry | `id` (INTEGER) | `timestamp`, `src_ip`, `protocol`, `threat_score`, `threat_level` |
| 6 | `traffic_stats` | Aggregated traffic volume | `id` (INTEGER) | `id` |
| 7 | `events` | Honeypot raw events | `id` (INTEGER) | `session_id`, `source_ip`, `timestamp` |
| 8 | `honeypot_nodes` | Honeypot daemon status | `id` (INTEGER) | `node_id` (UNIQUE) |
| 9 | `policies` | Deception policy configs | `id` (INTEGER) | `name` (UNIQUE) |
| 10 | `scheduled_reports` | Automated report delivery schedules | `id` (INTEGER) | `name` |
| 11 | `case_evidence` | Linked artifacts per case | `id` (INTEGER) | `case_id` |
| 12 | `search_history` | Analyst query history | `id` (INTEGER) | `id` |
| 13 | `pcap_captures` | Associated PCAP dumps | `id` (INTEGER) | `event_id` |
| 14 | `users` | PhantomNet users | `id` (INTEGER) | `username` (UNIQUE), `email` (UNIQUE) |
| 15 | `system_config` | Dynamic key-value configuration | `id` (INTEGER) | `key` (UNIQUE), `category` |
| 16 | `sentinel_playbooks` | Auto-generated defense playbooks | `id` (INTEGER) | `playbook_id` (UNIQUE), `status` |
| 17 | `sentinel_audit_logs` | Sentinel playbook action audits | `id` (INTEGER) | `playbook_id`, `timestamp` |

> [!WARNING]
> Notice that `events` currently lacks an `event_id` column for producer-generated UUIDv7 deduplication, and there are no tables for `refresh_tokens`, `taxii_clients`, or generic `audit_logs`. These will be introduced in Phases 1, 2, and 3.

---

## 4. Architecture & Security Posture Baseline

| Component | Baseline Observation | Risk / Assessment |
|---|---|---|
| **Event Ingestion** | Direct, synchronous SQLite/PostgreSQL write in `db_logger.py` | High risk of event loss during DB restarts; no queue or spool buffer |
| **WebSocket** | Accepts connections without authentication in `realtime.py` | Anyone can stream live honeypot telemetry |
| **Secrets Management** | `.env` contains cleartext `POSTGRES_PASSWORD=postgres` and `JWT_SECRET` | Secret committed in VCS; insecure default fallback |
| **Container Isolation** | Honeypots share `app_net` bridge with PostgreSQL and API | If honeypot is compromised, attacker can probe PostgreSQL directly |
| **Migrations** | No Alembic migrations applied; raw `ALTER TABLE` in `database.py` | Schema drift risk between local SQLite and Docker PostgreSQL |
| **Observability** | No `/health/ready` or `/health/live` endpoints; no Prometheus counters | Blind to queue depth, ingestion latency, and event drops |
| **ML Evaluation** | Static test sets with risk of temporal data leakage | Accuracy unverified under time-series walk-forward or adversarial conditions |

---

## 5. Next Steps

Execution proceeds immediately to **Phase 1 — Security Lockdown**:
1. Implement token refresh family and reuse detection in `backend/middleware/auth.py` and `backend/database/models.py`.
2. Secure all 13 unauthenticated routers with `get_current_user` and `require_role`.
3. Harden Active Defense endpoints (`/active-defense/block/{ip}`) with Admin role, step-up confirmation, and structured audit logs.
4. Implement CSRF protection for mutating HTTP routes and cookie-based WebSocket authentication.
5. Implement per-honeypot HMAC-SHA256 producer authentication on the Ingestion Gateway.
6. Build comprehensive API integration test suite in `tests/api/`.
