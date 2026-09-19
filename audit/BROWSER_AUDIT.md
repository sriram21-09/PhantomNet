# PHANTOMNET V3 — FRONTEND & BROWSER SECURITY AUDIT REPORT

**Audit Date**: September 19, 2026  
**Auditors**: Frontend Engineering & Web Application Security Group  
**Target Git SHA**: `8c199f2877901773b1beb04f80e244f98d0f7e3f`  
**Frontend Location**: `frontend-dev/phantomnet-dashboard/`

---

## 1. Executive Summary

The PhantomNet frontend is a Single-Page Application (SPA) built with React 18, Vite, and Tailwind CSS. It communicates with the backend via REST APIs and a WebSocket stream for real-time threat telemetry.

While the UI components and design systems are modern and well-structured, the audit uncovered **two significant security and resilience defects**:
1. **Administrative JWT Token Stored in `localStorage` (P2)**: `AdminPanel.jsx` and `adminFetch.js` store administrative authentication tokens in browser `localStorage`, bypassing HttpOnly cookie protections and exposing administrative sessions to Cross-Site Scripting (XSS) extraction.
2. **WebSocket Reconnection Lacks Backoff & Jitter (P1 / RT-02 Failure)**: `RealTimeContext.jsx` implements a hardcoded 3-second fixed retry timer (`setTimeout(connect, 3000)`), directly contradicting the documented claim of "exponential backoff with full jitter".

---

## 2. In-Depth Findings

### Finding 1: Token Storage in LocalStorage (P2 / SEC-01 & SEC-03)
- **Code Locations**:
  - `frontend-dev/phantomnet-dashboard/src/components/AdminPanel.jsx`:
    ```javascript
    const handleLogin = async (e) => {
      // ...
      localStorage.setItem('admin_token', data.token);
    };
    ```
  - `frontend-dev/phantomnet-dashboard/src/utils/adminFetch.js`:
    ```javascript
    export const adminFetch = async (url, options = {}) => {
      const token = localStorage.getItem('admin_token');
      const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`,
      };
      // ...
    };
    ```
- **Security Impact**:
  - OWASP explicitly recommends storing session and access tokens in `HttpOnly`, `Secure`, `SameSite=Strict` cookies to mitigate credential theft via DOM-based XSS.
  - Storing tokens in `localStorage` allows any third-party script, injected inline script, or malicious npm dependency to access `localStorage.getItem('admin_token')` and exfiltrate administrator credentials.
- **Remediation**:
  - Transition authentication to use backend-issued `HttpOnly` session cookies. Remove all references to `localStorage.getItem('admin_token')`.

---

### Finding 2: Reconnection Logic Lacks Exponential Backoff & Jitter (P1 / RT-02 Failure)
- **Documented Claim in Matrix (RT-02)**:
  - "Client reconnection implements exponential backoff with full jitter (1s base, 30s cap) to prevent thundering herd during server restarts."
- **Code Reality**:
  - `frontend-dev/phantomnet-dashboard/src/context/RealTimeContext.jsx` lines 118-124:
    ```javascript
    ws.onclose = () => {
      setIsConnected(false);
      // Attempt reconnect after fixed delay
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
    };
    ```
- **Operational Impact**:
  - In the event of a backend restart or temporary network partition, every connected dashboard client will attempt reconnection exactly every 3.0 seconds.
  - With multiple operators or wall-mounted security dashboards running, this creates an uncoordinated thundering herd, overwhelming the backend WebSocket handler precisely when it is attempting to recover.
- **Remediation**:
  - Implement genuine exponential backoff with full jitter:
    ```javascript
    const base = 1000;
    const max = 30000;
    const delay = Math.random() * Math.min(max, base * Math.pow(2, retryCount));
    reconnectTimeoutRef.current = setTimeout(connect, delay);
    ```

---

### Finding 3: Container Port Conflict & Dev Environment State (P3)
- **Observation**:
  - `docker-compose.yml` maps the frontend to host port 3000 (`3000:8080`).
  - In local environments, port 3000 was already bound to an external container (`asterion-frontend-1`), preventing `phantomnet_frontend` from binding to port 3000.
  - The frontend Dockerfile builds an Nginx image running as non-root user `10001:10001` with `read_only: true` and appropriate `tmpfs` mounts for `/var/cache/nginx`, `/run`, and `/tmp`.
- **Remediation**:
  - Make the host port configurable via environment variable in `docker-compose.yml`:
    ```yaml
    ports:
      - "${FRONTEND_PORT:-3000}:8080"
    ```

---

## 3. Frontend Audit Scorecard

| Check | Status | Notes |
| :--- | :---: | :--- |
| **Component Modularity** | 🟢 Pass | Clean separation of contexts, hooks, and views. |
| **Responsive Design** | 🟢 Pass | Tailwind responsive classes used consistently. |
| **XSS Defense (HTML escaping)** | 🟢 Pass | React JSX automatic escaping prevents basic HTML injection. |
| **Authentication Token Security** | 🔴 Fail | `admin_token` stored in `localStorage` and sent via Bearer header. |
| **WebSocket Reconnection Jitter** | 🔴 Fail | Fixed 3-second retry; no backoff, no jitter. |
| **Error Boundaries** | 🟡 Partial | Some top-level boundaries present, but nested widget failures can crash panels. |
