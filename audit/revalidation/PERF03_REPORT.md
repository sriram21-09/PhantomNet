# PhantomNet V3 — Live Ingestion Load & Resource Saturation Report (DUR-01, PERF-01, PERF-03)
**Date**: September 19, 2026  
**Auditor**: Independent Performance & SRE Audit Group  
**Target Infrastructure**: Live Docker Container Stack (`phantomnet_api`, `phantomnet_redis`, `phantomnet_postgres`)  
**Network Protocol**: Real TCP HTTP Sockets (`http://localhost:8000/api/v1/ingest/event`)

---

## 1. Executive Summary & Verdict

- **DUR-01 (Ingestion 500 EPS)**: **FAIL**
- **PERF-01 (P99 Latency < 100ms)**: **FAIL** (Actual: 5069.68ms)
- **PERF-03 (Resource Saturation)**: Documented below across sustained 500 EPS and burst 1,000 EPS.

---

## 2. Ingestion Load Results Table

| Phase | Target EPS | Duration | Submitted | Acknowledged (202) | Lost | Actual Throughput | P50 (ms) | P95 (ms) | P99 (ms) | Max (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **500 EPS Sustained** | 500 | 10s | 5000 | 0 | 5000 | 9.9 | 5019.55 | 5044.98 | 5069.68 | 5270.02 |
| **1000 EPS Burst** | 1000 | 5s | 5000 | 0 | 5000 | 10.9 | 5019.91 | 5036.84 | 5043.33 | 5053.72 |

---

## 3. Status Code Distribution
- **500 EPS**: {0: 5000}
- **1000 EPS**: {0: 5000}
