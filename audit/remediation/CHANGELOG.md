# PhantomNet V3 — Remediation & Revalidation Changelog

All changes documented below were implemented, verified, and benchmarked against live runtime components without synthetic substitution or mocked services.

---

## [3.0.1-remediated] - 2026-09-19

### Gate 1 — SEC-01: Route Authentication & Origin Verification
- **`backend/api/model_metrics.py`**: Added `Depends(get_current_user)` to all model metric and registry query endpoints.
- **`backend/api/sentinel.py`**: Added `Depends(get_current_user)` to both `/api/sentinel/*` and `/api/v1/sentinel/*` router definitions.
- **`backend/api/threat_intel.py`**: Protected `/api/v1/threat-intel/*` with `Depends(get_current_user)`.
- **`backend/api/pattern_analytics.py`**: Protected `/api/v1/patterns/*` with `Depends(get_current_user)`.
- **`backend/api/threat_scoring.py`**: Protected `/api/v1/analyze/*` with `Depends(get_current_user)`.
- **`backend/main.py`**: Added authentication guards to legacy `/analyze-traffic` and `/api/stats` routes.
- **`backend/api/admin.py`**: Added `GET /api/v1/admin/me` for cookie session validation and protected `/logout` with `Depends(get_current_user)`.
- **`backend/api/ingest.py`**: Enforced honeypot HMAC origin authentication header verification (`X-Honeypot-Signature`, `X-Honeypot-ID`, `X-Timestamp`) prior to body ingestion.
- **`audit/remediation/sec01_route_auth_matrix_after.json`**: Probed 127 registered endpoints across 5 credential states (Anonymous, Invalid Token, Expired Token, Analyst, Admin) on live container `http://localhost:8000`. Result: 0 unprotected endpoints remaining.

---

### Gate 2 — DUR-01 / PERF-01: Async Ingestion & Concurrency
- **`backend/services/ingestion_gateway.py`**: Refactored ingestion gateway using `redis.asyncio.Redis` for non-blocking stream operations (`xadd`, `pipeline`). Retained synchronous fallback for standalone unit tests.
- **`backend/api/ingest.py`**: Updated `/api/v1/ingest/event` and `/api/v1/ingest/batch` to asynchronously await `ingest_event_async` and `ingest_batch_async`.
- **`Dockerfile`**: Replaced development single-worker `uvicorn --reload` command with production multi-worker execution: `uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4 --proxy-headers`.
- **`audit/remediation/live_load_test_remediation.py`**: Conducted live TCP load tests against running container stack. Achieved 215.3 EPS sustained throughput with 99.14% delivery, eliminating prior complete event loop starvation.

---

### Gate 3 — ML-01 / ML-02 / ML-03: Machine Learning & Adversarial Robustness
- **`backend/ml/threat_scoring_service.py`**: Removed artificial adversarial shortcut `if context.is_malicious: return "CRITICAL"`. All inputs are now scored by actual feature extraction and model inference.
- **`tests/ml/test_adversarial.py`**: Removed `is_malicious=True` bypass from `test_payload_mutation_and_evasion`.
- **`audit/remediation/evaluate_ml_remediation.py`**: Evaluated models against `data/ground_truth.csv` using strict chronological split (70% train, 15% val, 15% test) with zero temporal leakage.
- **`ml_models/registry/models_index.json`**: Updated with empirical test set metrics (Accuracy: 0.7333, Precision: 0.0, Recall: 0.0, F1: 0.0, PR-AUC: 0.3951, AUC: 0.5597).

---

### Gate 4 — RT-02: WebSocket Reconnection Backoff
- **`frontend-dev/phantomnet-dashboard/src/context/RealTimeContext.jsx`**: Replaced static `setTimeout(connect, 3000)` with bounded exponential backoff and full jitter (`BASE_DELAY = 1000`, `MAX_DELAY = 30000`, `BACKOFF_FACTOR = 2`). Added timer cancellation and attempt reset on successful connection.
- **`audit/remediation/verify_gate4_rt02.py`**: Verified bounded delay, exponential growth, maximum 30s cap, full jitter distribution, connection reset, and unmount cleanup across 1,000 trials per attempt.

---

### Gate 5 — UI-01: Administrative Token Storage
- **`frontend-dev/phantomnet-dashboard/src/utils/adminFetch.js`**: Removed `localStorage.getItem('admin_token')` and `Authorization: Bearer` extraction. Implemented `credentials: 'include'` for automatic browser cookie transmission.
- **`frontend-dev/phantomnet-dashboard/src/pages/AdminPanel.jsx`**: Migrated `AdminGuard` and `AdminPanel` to use `GET /api/v1/admin/me` with `credentials: 'include'`. Removed all `localStorage.setItem('admin_token')` operations.
- **`backend/middleware/auth.py`**: Configured `HttpOnly`, `SameSite=strict`, and `Secure` attributes on `phantomnet_access_token` and `phantomnet_refresh_token` cookies.
- **`audit/remediation/verify_gate5_ui01.py`**: Verified login cookie issuance, authenticated `/me` retrieval, unauthenticated 401 rejection, logout cookie clearance (`Max-Age=0`), and zero JWT token storage in `localStorage`.

---

### Secondary Security & Operations Remediations
- **SEC-10 (Dual-Key JWT Rotation)**:
  - Added `get_previous_jwt_secret()` and dual-key verification fallback to `backend/middleware/auth.py:decode_token`.
  - Verified zero-downtime rotation in `audit/remediation/verify_sec10_jwt_rotation.py`.
- **SEC-11 (Honeypot Network Isolation)**:
  - Isolated honeypot containers strictly on `phantomnet_honeypot_net` (`internal: true`).
  - Verified via real socket tests from inside `phantomnet_ssh` and `phantomnet_http` that `postgres:5432`, `redis:6379`, and `prometheus:9090` are blocked while `api:8000` is allowed.
- **OPS-01 (Container Hardening)**:
  - Verified non-root UID `10001:10001`, `cap_drop: ALL`, `no-new-privileges: true`, `read_only: true` root filesystem.
  - Verified authorized writes to `/app/backend/logs` succeed while unauthorized root writes are blocked (`[Errno 30] Read-only file system`).
- **GOV-02 (PostgreSQL PITR Drill)**:
  - Executed physical base backup, WAL archiving, timestamp marker insertion, and point-in-time recovery drill in isolated environment.
