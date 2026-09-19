# PHANTOMNET V3 — MASTER FINDINGS REGISTER

**Audit Date**: September 19, 2026  
**Auditors**: Independent Senior Production Readiness & Security Audit Team  
**Target Git SHA**: `8c199f2877901773b1beb04f80e244f98d0f7e3f`  
**Total Findings**: 24 (2 Critical, 8 High, 10 Medium, 4 Low)

---

## 1. Severity Distribution

```
  [P0: CRITICAL]   ██ 2 findings       (Immediate security breach / container startup failure)
  [P1: HIGH]       ████████ 8 findings       (Data loss / synthetic ML / unauthenticated ops / false load test)
  [P2: MEDIUM]     ██████████ 10 findings      (False confidence tests / simulated isolation / token storage)
  [P3: LOW]        ████ 4 findings       (Documentation drift / minor cosmetic inconsistencies)
```

---

## 2. Critical Findings (P0)

### [FINDING-01] 29 Non-Public API Endpoints Completely Lack Authentication
- **Severity**: **P0 (Critical)**
- **Category**: Security (SEC-01)
- **Affected Files**:
  - `backend/api/sentinel.py`
  - `backend/routes/model_routes.py`
  - `backend/routes/enrichment_routes.py`
  - `backend/main.py`
- **Description**:
  Out of 134 registered routes in FastAPI, 29 non-public routes have no authentication dependencies (`Depends(get_current_user)` or `Depends(get_current_active_user)`). Any unauthenticated user can invoke these endpoints.
- **Affected Endpoints**:
  - `POST /api/sentinel/generate`
  - `GET /api/sentinel/rules/export-all`
  - `GET /api/sentinel/playbooks`
  - `GET /api/sentinel/playbooks/{playbook_id}`
  - `POST /api/sentinel/playbooks`
  - `PUT /api/sentinel/playbooks/{playbook_id}`
  - `DELETE /api/sentinel/playbooks/{playbook_id}`
  - `GET /api/sentinel/stats`
  - `GET /api/sentinel/audit-logs` (uses `get_optional_current_user`)
  - `GET /api/v1/model/metrics`
  - `GET /api/v1/model/features`
  - `POST /analyze-traffic`
  - `GET /api/stats`
  - `GET /api/v1/enrich/cache/stats`
  - Plus 15 additional internal Sentinel and enrichment subroutes.
- **Reproduction**:
  ```bash
  curl -X POST http://localhost:8000/api/sentinel/generate -H "Content-Type: application/json" -d '{"prompt": "test"}'
  curl -X GET http://localhost:8000/api/sentinel/rules/export-all
  ```
  Both return HTTP 200 OK without any `Authorization` header.
- **Impact**: Unauthorized access to internal security playbooks, Sigma/YARA detection logic, ML model architecture, and ability to trigger costly LLM generation loops.
- **Remediation**:
  Apply `dependencies=[Depends(get_current_active_user)]` to all APIRouter definitions in `api/sentinel.py`, `backend/routes/model_routes.py`, and `backend/routes/enrichment_routes.py`.

---

### [FINDING-02] Docker API Container Crashes at Startup on Read-Only Filesystem & Secret Filter
- **Severity**: **P0 (Critical)**
- **Category**: Operations (OPS-01) & Security (SEC-10)
- **Affected Files**:
  - `docker-compose.yml` (lines 241-277)
  - `backend/logging/logger.py` (line 14)
  - `backend/middleware/auth.py` (lines 47-51)
- **Description**:
  When launching `docker compose up api`:
  1. `docker-compose.yml` sets `read_only: true` on the `api` container.
  2. `backend/logging/logger.py` executes `os.makedirs('/app/backend/logs', exist_ok=True)`. Because `/app/backend/logs` is not mounted as a writable volume or tmpfs, the OS returns `OSError: [Errno 30] Read-only file system: '/app/backend/logs'`, causing uvicorn to crash immediately.
  3. Furthermore, `docker-compose.yml` sets `ENVIRONMENT: production` with default `JWT_SECRET: ${JWT_SECRET:-supersecret}`. `auth.py` terminates the process if `ENVIRONMENT == 'production'` and `JWT_SECRET` is in `_INSECURE_DEFAULTS` (`supersecret` and `your-super-secret-jwt-key-change-in-production`).
- **Reproduction**:
  ```bash
  docker compose up api
  docker logs phantomnet_api
  ```
- **Impact**: The API container enters an infinite crash loop out of the box in production mode.
- **Remediation**:
  1. Add `/app/backend/logs` to `tmpfs` in `docker-compose.yml`:
     ```yaml
     tmpfs:
       - /tmp:rw,noexec,nosuid,size=128m
       - /run:rw,noexec,nosuid,size=32m
       - /app/backend/logs:rw,noexec,nosuid,size=64m
     ```
  2. Ensure deployment documentation and automated bootstrap scripts generate and inject a 64-char hex secret before launching Compose.

---

## 3. High Findings (P1)

### [FINDING-03] Ingestion 500 EPS & P99 Latency Tests Execute on In-Memory FakeRedis & SQLite
- **Severity**: **P1 (High)**
- **Category**: Durability (DUR-01) & Performance (PERF-01)
- **Affected Files**:
  - `tests/load_tests/test_sustained_500eps.py`
- **Description**:
  The benchmark cited to prove 500 EPS and P99 latency < 100ms runs against `fakeredis.FakeStrictRedis` and an in-memory SQLite database (`sqlite:///:memory:`). The entire test completes 5,000 events in 1.07 seconds on a single thread.
- **Impact**: Zero empirical validation of network socket throughput, Redis Stream backpressure, or PostgreSQL WAL fsync. Production capacity under 500 EPS is completely unproven.
- **Remediation**:
  Replace `fakeredis` with a real multi-threaded load test (Locust or `k6`) targeting the live container stack over TCP sockets.

---

### [FINDING-04] Walk-Forward ML Benchmark Evaluated on 1,500 Synthetic Random Numbers
- **Severity**: **P1 (High)**
- **Category**: Machine Learning (ML-01 & ML-02)
- **Affected Files**:
  - `tests/ml/test_walk_forward_benchmark.py`
- **Description**:
  `test_walk_forward_benchmark.py` generates 1,500 rows of synthetic random data using `np.random.seed(42)` and trains a temporary Random Forest in 1.05 seconds. It never tests the committed model in `ml_models/registry/anomaly_detector.pkl` or real honeypot data.
- **Impact**: The documented ML metrics (Precision: 0.93, Recall: 0.79, F1: 0.86, FPR: 0.004) are fabricated from synthetic Gaussian distributions. Real anomaly detection performance is unknown.
- **Remediation**:
  Implement an offline evaluation script that loads `anomaly_detector.pkl` and evaluates it against real historical honeypot event logs from `data/pcaps/` or database records.

---

### [FINDING-05] Point-in-Time Recovery (PITR) Never Executed (Regex Search Only)
- **Severity**: **P1 (High)**
- **Category**: Governance (GOV-02)
- **Affected Files**:
  - `tests/test_pitr_recovery.py`
  - `scripts/dr_pitr_restore.sh`
- **Description**:
  `tests/test_pitr_recovery.py` only performs regex pattern matching on `docker-compose.yml` and `scripts/dr_pitr_restore.sh`. No backup was created, no WAL archive was generated, and no database restore was executed.
- **Impact**: Disaster recovery capabilities (RPO < 5 min, RTO < 15 min) are unproven. In a catastrophic storage failure, restore procedures may fail unexpectedly.
- **Remediation**:
  Implement an integration test that populates test rows, creates a base backup, archives WAL segments, simulates data corruption, and runs `dr_pitr_restore.sh` to confirm data recovery to a specific timestamp.

---

### [FINDING-06] Frontend WebSocket Reconnection Hardcodes 3-Second Fixed Delay
- **Severity**: **P1 (High)**
- **Category**: Real-Time (RT-02)
- **Affected Files**:
  - `frontend-dev/phantomnet-dashboard/src/context/RealTimeContext.jsx` (line 121)
- **Description**:
  While the matrix claims "exponential backoff with full jitter", `RealTimeContext.jsx` hardcodes `reconnectTimeoutRef.current = setTimeout(connect, 3000);`.
- **Impact**: In a server restart or network interruption, all connected clients will reconnect simultaneously every 3.0 seconds, creating a thundering herd against the WebSocket server.
- **Remediation**:
  Implement exponential backoff with full jitter (e.g. `Math.random() * Math.min(30000, 1000 * Math.pow(2, retries))`).

---

### [FINDING-07] Adversarial ML Test Bypasses Classifier via Hardcoded Boolean
- **Severity**: **P1 (High)**
- **Category**: Machine Learning (ML-03)
- **Affected Files**:
  - `tests/ml/test_adversarial.py`
  - `backend/services/threat_scoring_service.py`
- **Description**:
  The adversarial test constructs samples with `is_malicious: True`, triggering an early-exit rule in `threat_scoring_service.py` that immediately returns `CRITICAL`. The ML model is never invoked.
- **Impact**: Evasion resistance of the Random Forest model against obfuscated payloads is completely unverified.
- **Remediation**:
  Remove `is_malicious: True` from test payloads and pass adversarial feature vectors directly to `anomaly_detector.predict()`.

---

### [FINDING-08] Container Resource Saturation Evaluated on Mock Process Objects
- **Severity**: **P1 (High)**
- **Category**: Performance (PERF-03)
- **Affected Files**:
  - `tests/load_tests/test_resource_saturation.py`
- **Description**:
  `test_resource_saturation.py` uses `unittest.mock` to mock `psutil.virtual_memory()`. It never tests Docker cgroup CPU throttling or memory limits in a real Linux container.
- **Impact**: Behavior of the API container under memory pressure or OOM conditions remains uncharacterized.
- **Remediation**:
  Execute a stress test using `stress-ng` or `wrk` against a live container configured with CPU and memory limits.

---

### [FINDING-09] Live Container Stack Does Not Start Automatically via Test Suite
- **Severity**: **P1 (High)**
- **Category**: Operations (OPS-01)
- **Affected Files**:
  - `tests/`
- **Description**:
  The entire pytest suite runs without starting Docker containers. It passes 100% on a developer machine without Docker installed, creating the illusion of verified multi-container orchestration.
- **Impact**: Configuration mismatches between Docker Compose and the codebase remain undetected in CI.
- **Remediation**:
  Integrate `testcontainers-python` into CI to spin up real PostgreSQL and Redis containers for integration testing.

---

### [FINDING-10] Single-Key JWT Secrets Invalidate All Active Sessions on Rotation
- **Severity**: **P1 (High)**
- **Category**: Security (SEC-07)
- **Affected Files**:
  - `backend/middleware/auth.py`
- **Description**:
  `auth.py` supports only a single `JWT_SECRET`. When `scripts/rotate_secrets.py` rotates the secret, all active operator and administrator sessions are immediately terminated.
- **Impact**: Disrupts active incident response workflows during routine secret rotation.
- **Remediation**:
  Support dual-key verification (`JWT_SECRET_CURRENT` and `JWT_SECRET_PREVIOUS`) to allow existing tokens to expire naturally while signing new tokens with the new key.

---

## 4. Medium Findings (P2)

### [FINDING-11] Administrative Tokens Stored in Browser LocalStorage
- **Severity**: **P2 (Medium)**
- **Category**: Security (SEC-01 & SEC-03)
- **Affected Files**:
  - `frontend-dev/phantomnet-dashboard/src/components/AdminPanel.jsx`
  - `frontend-dev/phantomnet-dashboard/src/utils/adminFetch.js`
- **Description**:
  `AdminPanel.jsx` stores `admin_token` in `localStorage` and transmits it via `Authorization: Bearer` header.
- **Impact**: Tokens stored in `localStorage` are vulnerable to theft via Cross-Site Scripting (XSS).
- **Remediation**:
  Migrate administrative authentication to `HttpOnly`, `SameSite=Strict`, `Secure` cookies.

---

### [FINDING-12] Network Isolation Test Uses Mock Dictionary Lookups
- **Severity**: **P2 (Medium)**
- **Category**: Security (SEC-11)
- **Affected Files**:
  - `tests/ops/test_network_isolation.py`
- **Description**:
  `test_layer2_runtime_connectivity_boundary` tests a Python dictionary in memory rather than probing Docker network interfaces.
- **Impact**: Docker network isolation between honeypots and internal databases is not verified.
- **Remediation**:
  Execute `docker exec` socket probes verifying that honeypot containers cannot reach port 5432 on the `postgres` container.

---

### [FINDING-13] SHAP Feature Explainability Test Does Not Use SHAP
- **Severity**: **P2 (Medium)**
- **Category**: Machine Learning (ML-04)
- **Affected Files**:
  - `tests/ml/test_shap_consistency.py`
- **Description**:
  The test trains a 6-row Random Forest and asserts that `model.feature_importances_` is not empty. It does not import or execute `shap`.
- **Impact**: Instance-level SHAP attributions claimed in documentation are not provided.
- **Remediation**:
  Integrate `shap.TreeExplainer` or update documentation to state that global Gini feature importance is used.

---

### [FINDING-14] WebSocket Heartbeat Timeout Logic is Dead Code
- **Severity**: **P2 (Medium)**
- **Category**: Real-Time (RT-03)
- **Affected Files**:
  - `backend/api/realtime.py`
- **Description**:
  `HEARTBEAT_INTERVAL` and `HEARTBEAT_TIMEOUT` constants are defined, but no background task or ping/pong loop is implemented to terminate dead sockets.
- **Impact**: Zombie WebSocket connections may accumulate on the server if client connections terminate uncleanly.
- **Remediation**:
  Implement an asyncio ping/pong heartbeat loop that closes sockets exceeding `HEARTBEAT_TIMEOUT`.

---

### [FINDING-15] Database Query Latency Benchmarked on SQLite Only
- **Severity**: **P2 (Medium)**
- **Category**: Performance (PERF-02)
- **Affected Files**:
  - `tests/load_tests/test_query_latency.py`
- **Description**:
  Query performance (P95 < 200ms) was verified against an SQLite database file. PostgreSQL 15 query planning under large table volumes was not tested.
- **Impact**: Complex analytical queries on PostgreSQL may experience plan degradation or table locks under production loads.
- **Remediation**:
  Benchmark query latencies against PostgreSQL 15 seeded with 100,000+ realistic event rows.

---

### [FINDING-16] Redis Crash Recovery Test Uses Mock Client
- **Severity**: **P2 (Medium)**
- **Category**: Durability (DUR-03)
- **Affected Files**:
  - `tests/durability/test_redis_aof.py`
- **Description**:
  Redis AOF crash recovery was tested using a mocked Redis client object rather than terminating a running Redis container.
- **Impact**: Verification of `appendonly yes` fsync recovery after a sudden process crash is simulated.
- **Remediation**:
  Test AOF recovery by sending `kill -9` to a live Redis container and verifying state preservation upon restart.

---

### [FINDING-17] Peak 2,000 EPS Headroom Evaluated on In-Memory Fake Queue
- **Severity**: **P2 (Medium)**
- **Category**: Durability (DUR-02)
- **Affected Files**:
  - `tests/load_tests/test_peak_2000eps.py`
- **Description**:
  Peak 2,000 EPS burst headroom was tested using an in-memory queue. OS socket backlogs and Redis Stream buffer limits were not exercised.
- **Impact**: Sudden traffic bursts may drop connections at the TCP backlog layer.
- **Remediation**:
  Execute burst testing using a network load generator against the live API container.

---

### [FINDING-18] Redis Backpressure Handlers Tested via Injected Mock Exceptions
- **Severity**: **P2 (Medium)**
- **Category**: Durability (DUR-07)
- **Affected Files**:
  - `tests/durability/test_redis_backpressure.py`
- **Description**:
  Redis memory saturation was tested by injecting mock OOM exceptions into the client rather than filling Redis memory to the 512MB cap.
- **Impact**: Upstream producer behavior under real memory saturation is unverified.
- **Remediation**:
  Test backpressure by driving Redis memory usage to 512MB on a live instance.

---

### [FINDING-19] Secret Rotation Test Mocks File System Updates
- **Severity**: **P2 (Medium)**
- **Category**: Security (SEC-07)
- **Affected Files**:
  - `tests/ops/test_secret_rotation.py`
- **Description**:
  `test_secret_rotation.py` uses `unittest.mock.mock_open` to simulate `.env` file updates and environment reloading.
- **Impact**: Real-world file permission issues or process signal handling during rotation are not verified.
- **Remediation**:
  Test secret rotation on real temporary environment files with process reload verification.

---

### [FINDING-20] Database Backup Script Tested on SQLite Only
- **Severity**: **P2 (Medium)**
- **Category**: Operations (OPS-04)
- **Affected Files**:
  - `tests/ops/test_backup_restore.py`
- **Description**:
  Automated backup and restore testing exercised SQLite `iterdump` rather than PostgreSQL `pg_dump` and `pg_restore`.
- **Impact**: PostgreSQL-specific backup flags and permission constraints were not verified in CI.
- **Remediation**:
  Execute backup and restore tests against a running PostgreSQL 15 container.

---

## 5. Low Findings (P3)

### [FINDING-21] Anonymous Access Permitted to Sentinel Audit Logs
- **Severity**: **P3 (Low)**
- **Category**: Security (SEC-01 & SEC-08)
- **Affected Files**:
  - `backend/api/sentinel.py` (`/api/sentinel/audit-logs`)
- **Description**:
  `/api/sentinel/audit-logs` uses `get_optional_current_user` instead of `get_current_active_user`, allowing unauthenticated users to view audit log entries. Note: `/api/v1/sentinel/audit-logs` requires authentication.
- **Remediation**:
  Enforce `get_current_active_user` on `/api/sentinel/audit-logs`.

---

### [FINDING-22] Frontend Container Port Conflict on Port 3000
- **Severity**: **P3 (Low)**
- **Category**: Operations (OPS-01)
- **Affected Files**:
  - `docker-compose.yml`
- **Description**:
  Hardcoded host port 3000 in `docker-compose.yml` conflicts with pre-existing services or other local development containers.
- **Remediation**:
  Use `${FRONTEND_PORT:-3000}:8080` in `docker-compose.yml`.

---

### [FINDING-23] Redundant Route Registration Between Main and Sentinel Routers
- **Severity**: **P3 (Low)**
- **Category**: Architecture & Code Quality
- **Affected Files**:
  - `backend/main.py`
  - `backend/api/sentinel.py`
- **Description**:
  Certain Sentinel routes are registered both under `/api/sentinel/*` and `/api/v1/sentinel/*` with differing authentication dependencies.
- **Remediation**:
  Standardize all routes under `/api/v1/*` with consistent authentication dependencies.

---

### [FINDING-24] Missing Integration Test Execution in CI Workflow
- **Severity**: **P3 (Low)**
- **Category**: DevSecOps (OPS-06)
- **Affected Files**:
  - `.github/workflows/ci.yml`
- **Description**:
  CI workflow runs unit tests but does not spin up Docker Compose to run live integration or end-to-end tests.
- **Remediation**:
  Add an integration test job in GitHub Actions using Docker Compose.
