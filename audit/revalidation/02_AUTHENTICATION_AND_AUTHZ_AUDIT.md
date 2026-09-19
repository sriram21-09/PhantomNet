# PHANTOMNET V3 — AUTHENTICATION & AUTHORIZATION REVALIDATION AUDIT

**Date**: September 19, 2026  
**Auditor**: Application Security Verification Group  
**Dimensions Covered**: SEC-01, SEC-02, SEC-03, SEC-04, SEC-08, SEC-10, UI-01  

---

## 1. Executive Summary

While internal RBAC (SEC-02) and honeypot HMAC-SHA256 origin signing (SEC-03) are functional and well-engineered, **SEC-01 is 🔴 NOT VERIFIED** due to 37 exposed API routes. Furthermore, browser token storage (UI-01) utilizes `localStorage`, and secret rotation (SEC-10) lacks dual-key transition support.

---

## 2. Detailed Dimension Analysis

### SEC-01: Dynamic Route Authentication (🔴 NOT VERIFIED — P0)
- **Claim**: All non-public API endpoints require valid JWT authentication.
- **Evidence**: `audit/revalidation/sec01_route_tester.py` dynamically evaluated 132 routes in `phantomnet_api` across 5 states: Anonymous, Invalid Bearer, Expired Bearer, Analyst Role, and Admin Role.
- **Finding**: **37 non-public routes returned HTTP 200 OK to unauthenticated anonymous requests**:
  - `/api/v1/model/*` (`/metrics`, `/drift`, `/confusion_matrix`, `/retrain`, `/status`)
  - `/api/sentinel/*` (`/playbooks`, `/generate`, `/execute`, `/status`)
  - `/api/v1/patterns/*` (`/active`, `/analytics`, `/summary`)
  - `/api/stats`, `/api/overview`, `/analyze-traffic`
- **Root Cause**: FastAPIRouter instances in `backend/api/model_metrics.py`, `backend/api/sentinel.py`, `backend/api/threat_intel.py`, `backend/api/topology.py`, and `backend/main.py` were instantiated without `dependencies=[Depends(get_current_active_user)]`.

### SEC-02: Role-Based Access Control (🟢 VERIFIED — P2)
- **Claim**: Administrative routes are protected against Analyst-level credentials.
- **Evidence**: Dynamic probing confirmed that Analyst credentials attempting to access `/api/v1/admin/*` and `/api/v1/auth/users` were rejected with `HTTP 403 Forbidden`.
- **Verdict**: PASS.

### SEC-03: Honeypot Ingestion Origin Authentication (🟢 VERIFIED — P0)
- **Claim**: Event ingestion requires HMAC-SHA256 signature generated with `HONEYPOT_SECRET_KEY`.
- **Evidence**:
  - Tested `POST /api/v1/ingest/event` with unsigned payload: rejected with `HTTP 401 Unauthorized ("Missing required honeypot origin signature headers")`.
  - Tested with invalid secret signature: rejected with `HTTP 401 Unauthorized ("Signature mismatch / invalid origin credentials")`.
  - Tested with valid signature: accepted with `HTTP 202 Accepted`.
  - In production mode, weak or default keys are rejected on boot.
- **Verdict**: PASS.

### SEC-04: Replay Attack Prevention (🟢 VERIFIED — P1)
- **Claim**: Requests outside the freshness window are rejected.
- **Evidence**: `backend/services/origin_auth.py` enforces `max_drift_seconds = 60`. Ingestion requests with timestamps older than 60 seconds returned `HTTP 401 Unauthorized ("Timestamp drift exceeded")`.
- **Verdict**: PASS.

### SEC-08: Rate Limiting (🟢 VERIFIED — P2)
- **Claim**: Sensitive endpoints are protected against brute-force attacks.
- **Evidence**: SlowAPI rate limiting middleware active on `/api/v1/auth/token`.
- **Verdict**: PASS.

### SEC-10: Secret Lifecycle & Rotation (🔴 NOT VERIFIED — P1)
- **Claim**: Zero-downtime secret rotation without dropping active user sessions.
- **Evidence**: `audit/revalidation/test_secrets_rotation.py` confirmed that `SECRET_KEY` in `backend/middleware/auth.py` is a single static string. When rotated, all existing in-flight tokens fail validation immediately. Dual-key / JWKS transition is not implemented.
- **Verdict**: FAIL.

### UI-01: Authentication Token Storage Security (🔴 NOT VERIFIED — P2)
- **Claim**: Authentication tokens are stored securely to mitigate XSS risks.
- **Evidence**: Code inspection of `frontend-dev/phantomnet-dashboard/src/pages/AdminPanel.jsx` and `src/services/adminFetch.js`:
  ```javascript
  localStorage.setItem('admin_token', token);
  headers['Authorization'] = `Bearer ${localStorage.getItem('admin_token')}`;
  ```
  Storing JWTs in `localStorage` exposes them to complete exfiltration via any Cross-Site Scripting (XSS) vulnerability.
- **Verdict**: FAIL.

---

## 3. Required Remediation Plan
1. Add `dependencies=[Depends(get_current_active_user)]` to all 37 exposed router definitions.
2. Migrate frontend token storage from `localStorage` to `HttpOnly`, `Secure`, `SameSite=Strict` session cookies.
3. Implement dual-key JWT decoding in `backend/middleware/auth.py` (`CURRENT_SECRET` + `PREVIOUS_SECRET`).
