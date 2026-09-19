# PHANTOMNET V3 — SECURITY AUDIT REPORT (SEC-01 TO SEC-11)

**Audit Date**: September 19, 2026  
**Auditors**: Application Security & DevSecOps Engineering Group  
**Target Git SHA**: `8c199f2877901773b1beb04f80e244f98d0f7e3f`  
**Claimed Status**: 11 / 11 Verified (100%)  
**Audited Status**: **6 Verified (54.5%)**, **3 Partially Verified (27.3%)**, **2 Not Verified (18.2%)**

---

## 1. Domain Summary & Scorecard

| Dimension ID | Dimension Name | Claimed Status | Audited Status | Risk Level | Evidence Level | Verdict |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **SEC-01** | Global API Authentication | VERIFIED | 🔴 **NOT VERIFIED** | **P0 (Critical)** | Level 1 (Runtime) / Level 3 (Static) | 29 non-public endpoints lack authentication. Live container crashes on default secrets. |
| **SEC-02** | RBAC & Authorization | VERIFIED | 🟢 **VERIFIED** | P2 (Medium) | Level 2 (Test) / Level 3 (Static) | `require_role(["ADMIN"])` enforced on admin routes. Non-admin roles rejected with 403. |
| **SEC-03** | Ingestion Token Validation | VERIFIED | 🟢 **VERIFIED** | P1 (High) | Level 1 (Runtime) / Level 2 (Test) | Constant-time HMAC-SHA256 signature verification in ingestion gateway. |
| **SEC-04** | Replay Attack Mitigation | VERIFIED | 🟢 **VERIFIED** | P1 (High) | Level 2 (Test) / Level 3 (Static) | Redis-backed nonce cache (`SET NX EX 300`). Replays rejected with 409. |
| **SEC-05** | Threat Scoring Fail-Closed | VERIFIED | 🟢 **VERIFIED** | P1 (High) | Level 2 (Test) / Level 3 (Static) | `score_threat()` fails closed to `CRITICAL` (score 1.0) on service/model exceptions. |
| **SEC-06** | Sensitive Data Redaction | VERIFIED | 🟢 **VERIFIED** | P2 (Medium) | Level 2 (Test) / Level 3 (Static) | Passwords, tokens, and authorization headers redacted in logs via regex maskers. |
| **SEC-07** | Secret Rotation Protocol | VERIFIED | 🟡 **PARTIALLY VERIFIED** | P2 (Medium) | Level 3 (Static) | Script exists but tests mock file updates. Multi-version JWT verification missing. |
| **SEC-08** | Audit Log Tamper Resistance | VERIFIED | 🟢 **VERIFIED** | P2 (Medium) | Level 2 (Test) / Level 3 (Static) | HMAC/SHA-256 hash chaining implemented in database. Note: read endpoint unauthenticated. |
| **SEC-09** | Input Validation & Sanitization | VERIFIED | 🟢 **VERIFIED** | P1 (High) | Level 1 (Runtime) / Level 2 (Test) | Pydantic v2 schemas reject malformed IP, invalid port, oversized payload. |
| **SEC-10** | Container Least Privilege | VERIFIED | 🟡 **PARTIALLY VERIFIED** | **P0 (Critical)** | Level 1 (Runtime) | Non-root user specified. However, container crashes at startup on read-only `/app/backend/logs`. |
| **SEC-11** | Network Isolation & Segmentation | VERIFIED | 🟡 **PARTIALLY VERIFIED** | P2 (Medium) | Level 3 (Static) | 3 Docker bridge networks configured. However, tests use mock dict lookup, not socket probes. |

---

## 2. In-Depth Analysis by Dimension

### SEC-01: Global API Authentication (🔴 NOT VERIFIED — P0)
- **Claim**: 100% of non-public API endpoints require valid JWT authentication.
- **Audited Reality**:
  - Out of 134 total registered routes, 8 are public (health probes, docs, login), 97 are authenticated, and **29 non-public routes have NO authentication dependencies**.
  - **Exposed Unauthenticated Endpoints**:
    1. `POST /api/sentinel/generate`: Allows anonymous users to trigger LLM-based Sentinel rule generation.
    2. `GET /api/sentinel/rules/export-all`: Allows anonymous users to download all generated Sigma and YARA rules.
    3. `GET /api/sentinel/playbooks`: Allows anonymous users to list internal incident response playbooks.
    4. `GET /api/sentinel/stats`: Allows anonymous users to view Sentinel pipeline statistics.
    5. `GET /api/sentinel/audit-logs`: Uses `get_optional_current_user` and permits anonymous log retrieval.
    6. `GET /api/v1/model/metrics`: Exposes ML model accuracy and performance metrics without authentication.
    7. `GET /api/v1/model/features`: Exposes internal feature definitions without authentication.
    8. `POST /analyze-traffic`: Allows arbitrary traffic analysis submissions without credentials.
    9. `GET /api/stats`: Exposes backend platform telemetry to unauthenticated callers.
    10. `GET /api/v1/enrich/cache/stats`: Exposes cache statistics to unauthenticated callers.
  - **Test Flaw**: `tests/api/test_auth.py` only tests 8 cherry-picked endpoints (`/api/v1/events`, `/api/v1/alerts`, `/api/v1/incidents`, `/api/v1/honeypots`, `/api/v1/threat-intelligence`, `/api/v1/admin/users`, `/api/v1/metrics`, `/api/v1/export`). It completely ignores `api/sentinel.py`, `backend/routes/model_routes.py`, `backend/routes/enrichment_routes.py`, and `backend/main.py`.

### SEC-02: Role-Based Access Control (🟢 VERIFIED)
- **Implementation**: `require_role(["ADMIN"])` dependency in `backend/middleware/auth.py`.
- **Validation**: Probed with `ANALYST`, `OPERATOR`, and `AUDITOR` roles. Attempting to access `/api/v1/admin/*` or trigger honeypot administration returned HTTP 403 Forbidden with `{"detail": "Insufficient permissions"}`.
- **Evidence**: `audit/logs/sec_02_rbac_authorization.log`.

### SEC-03: Ingestion Token Validation (🟢 VERIFIED)
- **Implementation**: `backend/api/ingestion.py` validates incoming honeypot events via HMAC-SHA256 signature in `X-Signature` header using `hmac.compare_digest`.
- **Validation**: 
  - Missing signature -> HTTP 401 Unauthorized.
  - Forged signature -> HTTP 403 Forbidden.
  - Valid signature -> HTTP 202 Accepted.
- **Evidence**: `audit/logs/sec_03_ingestion_token.log`.

### SEC-04: Replay Attack Mitigation (🟢 VERIFIED)
- **Implementation**: Nonce verification in `backend/api/ingestion.py` using Redis `SET nonce:UUID EX 300 NX`.
- **Validation**: Submitting the same valid event payload with an identical nonce twice rejected the second request with HTTP 409 Conflict (`{"detail": "Nonce already used or expired"}`).
- **Evidence**: `audit/logs/sec_04_replay_mitigation.log`.

### SEC-05: Threat Scoring Fail-Closed (🟢 VERIFIED)
- **Implementation**: `score_threat()` in `backend/services/threat_scoring_service.py` wraps ML inference and threat intel lookups in `try...except` blocks.
- **Validation**: When the ML service raises `RuntimeError` or the external intelligence API times out, the service defaults to severity `CRITICAL` (1.0), ensuring suspicious traffic is never silently allowed.
- **Evidence**: `audit/logs/sec_05_threat_scoring_fail_closed.log`.

### SEC-06: Sensitive Data Redaction (🟢 VERIFIED)
- **Implementation**: `backend/logging/logger.py` and `middleware/logging_middleware.py` apply regex filters replacing patterns matching `Bearer eyJ...`, `password=...`, and `secret=...` with `[REDACTED]`.
- **Validation**: Tested with sample log payloads containing API keys, passwords, and JWT tokens; all were redacted before writing to log streams.
- **Evidence**: `audit/logs/sec_06_sensitive_redaction.log`.

### SEC-07: Secret Rotation Protocol (🟡 PARTIALLY VERIFIED)
- **Implementation**: `scripts/rotate_secrets.py` exists to generate new keys and update configuration files.
- **Gaps**: 
  - The unit test `tests/ops/test_secret_rotation.py` mocks out file writes and environment reloading.
  - The JWT middleware does not support multi-version key verification (graceful dual-key rotation). Rotating `JWT_SECRET` immediately invalidates all active user sessions without grace period.
- **Evidence**: `audit/logs/sec_07_secret_rotation.log`.

### SEC-08: Audit Log Tamper Resistance (🟢 VERIFIED)
- **Implementation**: `backend/database/models.py` defines `AuditLog` with `previous_hash` and `current_hash` columns using SHA-256 HMAC chaining.
- **Validation**: Modifying an existing audit record's payload invalidates the cryptographic verification chain.
- **Caveat**: `/api/sentinel/audit-logs` endpoint has no authentication dependency and can be read by anonymous users.
- **Evidence**: `audit/logs/sec_08_audit_tamper_resistance.log`.

### SEC-09: Input Validation & Sanitization (🟢 VERIFIED)
- **Implementation**: Pydantic v2 schemas in `backend/schemas/` enforce IP address formatting (`ipaddress.IPv4Address`), port ranges (`1-65535`), and payload size limits.
- **Validation**: Tested 12 negative test vectors (SQL injection, path traversal, oversized bodies > 1MB, malformed JSON); all were rejected with HTTP 422 Unprocessable Entity or HTTP 400 Bad Request.
- **Evidence**: `audit/runtime/negative_test_results.json`.

### SEC-10: Container Least Privilege (🟡 PARTIALLY VERIFIED — P0)
- **Implementation**: `backend/api/Dockerfile` and `docker-compose.yml` set `user: "10001:10001"`, `cap_drop: [ALL]`, `no-new-privileges: true`, and `read_only: true`.
- **Runtime Failure**:
  - The container **crashes immediately upon boot** with:
    `OSError: [Errno 30] Read-only file system: '/app/backend/logs'`
  - `backend/logging/logger.py` attempts `os.makedirs('/app/backend/logs', exist_ok=True)`. Because `/app/backend/logs` is neither a tmpfs mount nor a writable volume, the container cannot start with `read_only: true`.
- **Evidence**: Docker container log `ce68ab94-94b6-4676-b2d2-2cc1d418b88c/task-302.log`.

### SEC-11: Network Isolation & Segmentation (🟡 PARTIALLY VERIFIED)
- **Implementation**: `docker-compose.yml` defines three isolated bridge networks: `app_net`, `honeypot_net` (`internal: true`), and `internal_broker_net` (`internal: true`).
- **Test Flaw**:
  - `tests/ops/test_network_isolation.py` contains `test_layer2_runtime_connectivity_boundary()`.
  - Instead of executing Docker socket probes (`docker exec curl ...`), the test defines a Python dictionary in memory:
    ```python
    allowed_hosts = {'api': ['postgres', 'redis'], 'honeypot': ['api']}
    def probe(src, dst): return dst in allowed_hosts.get(src, [])
    assert probe('honeypot', 'postgres') is False
    ```
  - This test merely asserts that a Python dictionary works; it provides zero empirical verification of Docker bridge iptables rules.
- **Evidence**: `audit/logs/sec_11_network_isolation.log`.

---

## 3. Remediation Roadmap

1. **[P0] SEC-01**: Add `dependencies=[Depends(get_current_active_user)]` to `api/sentinel.py`, `backend/routes/model_routes.py`, `backend/routes/enrichment_routes.py`, and `main.py`.
2. **[P0] SEC-10**: In `docker-compose.yml`, mount a volume or tmpfs at `/app/backend/logs` (e.g. `tmpfs: - /app/backend/logs:rw,noexec,nosuid,size=64m`) or redirect logging strictly to stdout.
3. **[P1] SEC-07**: Implement dual-key JWT verification (`JWT_SECRET_CURRENT` and `JWT_SECRET_PREVIOUS`) to enable zero-downtime secret rotation without logging out active users.
4. **[P2] SEC-11**: Replace dictionary-based test in `test_network_isolation.py` with real Docker exec socket probes verifying network boundaries.
