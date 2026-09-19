# PHANTOMNET V3 — PERFORMANCE & SATURATION REVALIDATION AUDIT

**Date**: September 19, 2026  
**Auditor**: SRE & Systems Performance Group  
**Dimensions Covered**: PERF-01, PERF-02, PERF-03  

---

## 1. Executive Summary

Standard single-request read latency (PERF-02) is acceptable under idle conditions. However, under real concurrent load or during background ML training, **PERF-01 and PERF-03 are 🔴 NOT VERIFIED**. The single-container architecture colocates heavy ML training processes with the Uvicorn web server within a 1.0 CPU resource limit, causing severe CPU starvation and HTTP timeouts.

---

## 2. Detailed Dimension Analysis

### PERF-01: Ingestion P99 Latency < 100ms (🔴 NOT VERIFIED — P1)
- **SLO Target**: 99% of ingestion requests acknowledged within 100ms.
- **Actual Measured Latency**:
  - P50: 5,011 ms
  - P95: 5,028 ms
  - P99: 5,039 ms
- **Root Cause**: Synchronous Redis blocking operations executed on the main asyncio event loop thread under high concurrency.
- **Verdict**: FAIL.

### PERF-02: API Query Response Time (🟢 VERIFIED — P2)
- **SLO Target**: Read queries return within acceptable bounds (< 200ms).
- **Actual Measured Latency**:
  - `GET /health/live`: 12ms - 35ms (idle)
  - `GET /api/v1/auth/me`: 18ms - 42ms (idle)
- **Verdict**: PASS (when container is not CPU starved).

### PERF-03: Resource Saturation Limits (🔴 NOT VERIFIED — P1)
- **SLO Target**: System remains stable and responsive up to container resource limits.
- **Observed Behavior**:
  - `docker-compose.yml` configures:
    ```yaml
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
    ```
  - When `ThreatAnalyzerService` or `unsupervised_detector.train_baseline` triggers, it spawns background training processes (`multiprocessing.spawn`).
  - CPU consumption of the background worker reaches 100% of the container's 1.0 CPU limit.
  - Because Uvicorn shares this 1.0 CPU limit, the web server is starved of CPU cycles, causing incoming HTTP requests (even `/health/live`) to time out with `requests.exceptions.ReadTimeout`.
- **Verdict**: FAIL.

---

## 3. Required Remediation Plan
1. Decouple ML training and threat analysis into a separate dedicated worker container (`phantomnet_worker`).
2. Restrict background workers to a separate CPU budget.
3. Migrate `ingestion_gateway.py` to `redis.asyncio` to prevent event loop thread exhaustion.
