# NEURAL OPERATIONS CENTER: REMEDIATION BASELINE
**Document:** NEURAL_OPERATIONS_CENTER_REMEDIATION_BASELINE.md  
**Date:** October 3, 2026  
**Status:** Pre-Remediation Verification Baseline  
**Target Route:** `/advanced-dashboard`  
**Page Component:** [`frontend-dev/phantomnet-dashboard/src/pages/AdvancedDashboard.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/pages/AdvancedDashboard.jsx)  

---

## 1. Confirmed Defects

The empirical forensic audit ([`NEURAL_OPERATIONS_CENTER_FORENSIC_AUDIT.md`](file:///c:/Users/srira/Project/PhantomNet/NEURAL_OPERATIONS_CENTER_FORENSIC_AUDIT.md)) identified 10 concrete defects across the Neural Operations Center page and its supporting backend services:

1. **NOC-DEF-01 (CRITICAL) — Broken Authentication on Predictive Analytics Endpoints:**
   - [`PredictiveAnalytics.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/components/PredictiveAnalytics.jsx#L20-L24) invokes `/api/v1/predictive/forecast`, `/api/v1/predictive/risk-score`, and `/api/v1/predictive/next-attack` using unauthenticated `fetch()` without headers or credentials.
   - Backend enforces `Depends(get_current_user)`, returning `HTTP 401 Unauthorized`.
   - Error is silently swallowed by `catch {}`, permanently trapping the UI in mock fallback state.
2. **NOC-DEF-02 (CRITICAL) — Fabricated ML Model Claims ("LSTM-V3"):**
   - UI renders `"LSTM-V3 ACTIVE"` badge; backend returns `"model": "LSTM-V3"`.
   - No LSTM model executes. The forecast is simple Python exponential smoothing (`alpha = 0.4`), the next-attack prediction is a SQL `GROUP BY protocol` query, and [`ml_models/lstm_attack_predictor.h5`](file:///c:/Users/srira/Project/PhantomNet/ml_models/lstm_attack_predictor.h5) is a 24-byte mock file containing `MOCK_H5_FILE_MAGIC_BYTES`.
3. **NOC-DEF-03 (HIGH) — Duplicate Nested `RealTimeProvider` Creating Dual WebSockets:**
   - [`App.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/App.jsx#L34) instantiates `<RealTimeProvider>` at the root.
   - [`AdvancedDashboard.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/pages/AdvancedDashboard.jsx#L62) nests a second `<RealTimeProvider>`, creating 2 simultaneous WebSocket connections to `/api/v1/realtime/ws` per browser tab, exhausting server connection limits.
4. **NOC-DEF-04 (HIGH) — Threat Score Scale Mismatch (0.0–1.0 vs 0–100):**
   - Backend WebSocket broadcasts `threat_score` as float `0.0–1.0` (e.g. `0.46`).
   - [`EventStream.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/components/EventStream.jsx#L41) and [`AttackAttribution.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/components/AttackAttribution.jsx#L55) test integer thresholds (`> 40`, `> 60`, `> 80`).
   - All events render as `0%` threat score, labels evaluate to `"LOW"`, and attackers are categorized as `"Amateur (Script Kiddie)"` with `"Unknown Scanner"`.
5. **NOC-DEF-05 (HIGH) — Dead Backend Architecture for Attack Attribution:**
   - [`backend/api/attack_attribution.py`](file:///c:/Users/srira/Project/PhantomNet/backend/api/attack_attribution.py) provides endpoints `/api/v1/attribution/profile/{ip}` and `/api/v1/attribution/top-attackers`.
   - [`AttackAttribution.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/components/AttackAttribution.jsx) completely ignores these endpoints and runs uncalibrated client heuristics on ephemeral WebSocket memory.
6. **NOC-DEF-06 (MEDIUM) — Missing Historical Telemetry Backfill on Mount:**
   - `LiveMetrics`, `AttackAttribution`, and `EventStream` rely solely on incoming WebSocket events without initial REST hydration, leaving panels in permanent loading/empty states if background traffic is idle.
7. **NOC-DEF-07 (MEDIUM) — Unsafe External Audio Asset Dependency:**
   - `EventStream.jsx` loads alert audio from `https://assets.mixkit.co/active_storage/sfx/2568/2568-preview.mp3`, introducing CSP and air-gapped failures.
8. **NOC-DEF-08 (MEDIUM) — Stale Database Dataset Resulting in Empty Rolling Windows:**
   - `backend/phantomnet.db` contains 315 rows dated prior to `2026-10-03 04:28:09`. Real-time rolling queries return 0 rows.
9. **NOC-DEF-09 (MEDIUM) — Complete Absence of Test Coverage:**
   - Zero frontend unit/E2E tests and zero functional API tests exist for NOC components and routes.
10. **NOC-DEF-10 (LOW) — Redundant UI Route & Competing Source of Truth:**
    - Route `/advanced-dashboard` duplicates and conflicts with canonical pages `/dashboard` and `/threat-analysis`.

---

## 2. Affected Files

### Frontend Files
- [`frontend-dev/phantomnet-dashboard/src/pages/AdvancedDashboard.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/pages/AdvancedDashboard.jsx) (Duplicate provider, header layout)
- [`frontend-dev/phantomnet-dashboard/src/components/PredictiveAnalytics.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/components/PredictiveAnalytics.jsx) (Auth failure, fake LSTM badge, silent error swallowing)
- [`frontend-dev/phantomnet-dashboard/src/components/AttackAttribution.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/components/AttackAttribution.jsx) (Bypassed backend API, scale mismatch, client heuristics)
- [`frontend-dev/phantomnet-dashboard/src/components/EventStream.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/components/EventStream.jsx) (0% score rendering, LOW label, external audio asset)
- [`frontend-dev/phantomnet-dashboard/src/components/LiveMetrics.jsx`](file:///c:/Users/srira/Project/PhantomNet/frontend-dev/phantomnet-dashboard/src/components/LiveMetrics.jsx) (Missing HTTP fallback on WS stall)
- New Utility: `frontend-dev/phantomnet-dashboard/src/utils/threatScore.js` (Canonical score normalization)

### Backend Files
- [`backend/api/predictive.py`](file:///c:/Users/srira/Project/PhantomNet/backend/api/predictive.py) (Remove "LSTM-V3" label; handle empty/insufficient data cleanly; preserve auth)
- [`backend/api/attack_attribution.py`](file:///c:/Users/srira/Project/PhantomNet/backend/api/attack_attribution.py) (Score normalization 0.0-1.0; canonical threshold alignment)

### Test Files to Create
- `tests/noc/test_predictive.py`
- `tests/noc/test_attribution.py`
- `tests/noc/test_threat_score_boundaries.py`
- `frontend-dev/phantomnet-dashboard/src/utils/__tests__/threatScore.test.js`

---

## 3. Actual API & Authentication Behavior

| Endpoint | Method | Auth Required | Unauth Response | Auth Response | Backend Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/v1/predictive/forecast` | GET | Yes (`Depends(get_current_user)`) | 401 Unauthorized | 200 OK | Functional statistical exponential smoothing |
| `/api/v1/predictive/risk-score` | GET | Yes (`Depends(get_current_user)`) | 401 Unauthorized | 200 OK | Functional SQL aggregation (30 min window) |
| `/api/v1/predictive/next-attack` | GET | Yes (`Depends(get_current_user)`) | 401 Unauthorized | 200 OK | Functional protocol heuristic; returns fake `"LSTM-V3"` |
| `/api/v1/attribution/top-attackers` | GET | Yes (`Depends(get_current_user)`) | 401 Unauthorized | 200 OK | Functional SQL grouping on `src_ip` (24h window) |
| `/api/v1/attribution/profile/{ip}` | GET | Yes (`Depends(get_current_user)`) | 401 Unauthorized | 200 OK | Functional attacker profile; uncalibrated score scale |

---

## 4. WebSocket Architecture

- Single production endpoint: `ws://localhost:8000/api/v1/realtime/ws`.
- Authenticated via session cookie `phantomnet_access_token` or `Authorization` header during handshake.
- Enforces CSWSH Origin validation (`ALLOWED_ORIGINS`).
- Managed by `RealTimeManager` in [`backend/api/realtime.py`](file:///c:/Users/srira/Project/PhantomNet/backend/api/realtime.py).
- Frontend subscription handled by `RealTimeContext.jsx` with exponential backoff and jitter.
- Defect: Nesting `<RealTimeProvider>` inside `AdvancedDashboard.jsx` opens 2 active WebSocket connections simultaneously.

---

## 5. Real Database Sources vs Canonical ML Sources

- **Database:** SQLite (`backend/phantomnet.db`), table `packet_logs` (315 records, all TCP, timestamps from 2026-10-01 to 2026-10-03 04:28:09).
- **Canonical ML Source:**
  - Feature Extractor: 12D Canonical Feature Schema (`CANONICAL_FEATURE_NAMES` in `backend/ml/config/feature_schema.py`).
  - Prediction Engine: 0.85 Random Forest + 0.15 Calibrated Isolation Forest in `backend/ml/models/ensemble_predictor.py`.
  - Severity Thresholds: `CRITICAL >= 0.80`, `HIGH >= 0.60`, `MEDIUM >= 0.40`, `LOW < 0.40`.
  - Enforcement Decisions: `BLOCK >= 0.80`, `ALERT >= 0.50`, `ALLOW < 0.50`.
- **NOC Decoupling:**
  - Neural Operations Center was excluded from canonical ML pipeline (`ML_REPOSITORY_INVENTORY.md` line 228).
  - Remediation must ground all threat scores and severities in the canonical thresholds.

---

## 6. Fabricated UI Values & Data Lineage Breakdown

| UI Element | Current Stated Value | Actual Source | Truthful Remediation Required |
| :--- | :--- | :--- | :--- |
| **Prediction Model Badge** | `"LSTM-V3 ACTIVE"` | Static string | Change to `"Statistical Forecast"` |
| **Model Name in API** | `"model": "LSTM-V3"` | Static string | Change to `"Statistical Trend Analysis"` |
| **Next Attack Target** | Hardcoded SSH fallback | Hardcoded dictionary | Display `"Insufficient data"` if no events in window |
| **Next Attack Confidence** | Hardcoded 42% fallback | Hardcoded integer | Display `"N/A"` if no events in window |
| **Countdown Timer** | T-MINUS 25m ticking down | Client `setInterval` | Display `"N/A"` or remove fictitious countdown |
| **Attacker Tools** | Nmap, Hydra, Metasploit | Client string matching | Sourced from backend attribution or labeled `"Unknown / Insufficient evidence"` |
| **Attacker Sophistication** | "Amateur (Script Kiddie)" | Client count check | Calibrated by backend canonical threat score |
| **Event Threat Score** | Rendered as `0%` | Unscaled `0.46` float | Canonical normalization: `0.46` displays as `46%` |
