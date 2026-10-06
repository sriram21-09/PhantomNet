# PHANTOMNET SYSTEM ADMINISTRATION — PRE-REMEDIATION BASELINE REPORT
**Date:** October 5, 2026  
**Auditor / Engineer:** Senior Full-Stack Security & DevOps Engineer  
**Scope:** Pre-Remediation State Assessment of System Administration Module  

---

## 1. Baseline Test Metrics
- **Backend Tests:** 23 tests in `backend/tests/test_api_security_audit.py` (all passed).
- **Frontend Admin Tests:** 0 tests dedicated to `AdminPanel.jsx`, `UserManagement.jsx`, `SystemConfig.jsx`, `Maintenance.jsx`.
- **Frontend ESLint Status:**
  - `AdminPanel.jsx`, `UserManagement.jsx`, `SystemConfig.jsx`, `Maintenance.jsx`: 0 errors, 0 warnings.
  - Overall repository: 2 errors, 3 warnings (located in `NetworkTopology.jsx`, `Dashboard.jsx`, `Events.jsx`, `exportUtils.test.js`).
- **Frontend Production Build:** Vite build successful in 1.46s (`dist/index.html` 0.89 kB, bundle size 944 kB).

---

## 2. Baseline API & Security Behavior
- **Authentication & RBAC:**
  - `/api/v1/admin/users`: 401 Unauthorized (unauth), 403 Forbidden (Viewer), 403 Forbidden (Analyst), 200 OK (Admin).
  - `/api/v1/admin/config` (GET): 401 Unauthorized (unauth), 403 Forbidden (Viewer), 200 OK (Analyst), 200 OK (Admin).
  - `/api/v1/admin/system-overview`: 401 Unauthorized (unauth), 403 Forbidden (Viewer), 200 OK (Analyst), 200 OK (Admin).
- **CSRF Enforcement:**
  - Reject cookie-authenticated mutating requests lacking `X-Requested-With` or `X-CSRF-Token` (403 Forbidden).
  - Reject requests with disallowed origins (403 Forbidden).
  - Accept requests from `http://localhost:3000` with `X-Requested-With: XMLHttpRequest`.

---

## 3. Baseline Defect State
- **Backup (DEF-ADM-01 & DEF-ADM-03):**
  - Invoking `POST /api/v1/admin/backup` throws `OSError: [Errno 30] Read-only file system: '/app/backups'` and returns HTTP 500.
  - Implementation in `admin.py` exports raw bcrypt `hashed_password` into JSON.
  - Packet logs are arbitrarily truncated to 5,000 records.
- **Restore (DEF-ADM-04):**
  - Frontend `Maintenance.jsx` contains a dead dropzone without `<input type="file">`.
  - Backend lacks `POST /api/v1/admin/restore`.
- **Audit Logging (DEF-ADM-02):**
  - `backend/services/audit_service.py` is never imported or called in `admin.py`.
  - Admin operations write 0 rows to `audit_logs` table (`SELECT count(*) FROM audit_logs` = 0).
- **System Health (DEF-ADM-05):**
  - Component statuses (`FastAPI Server`, `PostgreSQL Database`, `ML Engine`, `Real-Time WebSocket`, `Traffic Sniffer`) are hardcoded to `"online"`.
  - Uptime is hardcoded to `"Running"`.
- **Configuration Wiring (DEF-ADM-06):**
  - 14 of 16 settings are persisted to `system_config` table but never consumed by runtime honeypots, ML engine, or SIEM exporters.
- **Frontend Error Handling (DEF-ADM-07 & DEF-ADM-08):**
  - `SystemConfig.jsx:saveSection` displays false green "Saved successfully" banner even when backend PUT returns 403 or 500.
  - `UserManagement.jsx:fetchUsers` renders 401/403 errors as "No users found".
- **Admin Invariants (DEF-ADM-09):**
  - Admin can demote themselves to Viewer or disable their own account even if they are the sole admin.
- **Freshness & Real-Time (DEF-ADM-10):**
  - Pulsing "live" indicators in UI despite no WebSockets, SSE, or polling intervals.

---

## 4. Remediation Plan Overview
1. **Infrastructure & Storage:** Configure writable backup storage mount in `docker-compose.yml` (`api_backups:/app/backups`) or configurable `BACKUP_DIR`.
2. **Backend Services & Admin Router:**
   - Implement secure, sanitized, non-truncated backup routine omitting passwords and secrets.
   - Implement transactional restore endpoint with file validation, integrity checking, and size limits.
   - Wire `audit_log()` into all admin mutations.
   - Implement real subsystem health probes.
   - Enforce last-admin protection invariants.
   - Expose configuration getter helper and wire settings to runtime consumers.
3. **Frontend Components:**
   - Re-wire `Maintenance.jsx` with real restore file picker, confirmation, and status.
   - Fix error checking in `SystemConfig.jsx` and `UserManagement.jsx`.
   - Update `SystemOverview` with real status taxonomy, last updated timestamp, and manual refresh.
4. **Verification & Testing:**
   - New backend and frontend tests.
   - End-to-end browser verification via Playwright for Admin, Viewer, and Analyst.
