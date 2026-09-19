# PHANTOMNET V3 — TEST & EVIDENCE REALISM CLASSIFICATION

**Date**: September 19, 2026  
**Auditor**: Independent QA & Test Integrity Group  

---

## 1. Test Evidence Hierarchy (Tiers A through G)

To ensure unassailable audit credibility, every test in the PhantomNet repository is classified into one of seven evidence tiers based on its real-world validity:

- **Tier A (Runtime Executable Verification)**: Executed against live Docker containers, real network sockets, real PostgreSQL, and real Redis instances.
- **Tier B (Valid Integration Test)**: Automated test exercising real application components with valid database transactions or cryptographic logic.
- **Tier C (Static Code & Config Analysis)**: Verification based on AST parsing, declarative configuration inspection, or architectural boundary analysis.
- **Tier D (Documentation Only)**: Claim documented in markdown or comments without executable test backing.
- **Tier E (Flawed Test / False Confidence)**: Test passes, but relies on synthetic random numbers, `fakeredis`, or hardcoded bypasses that do not exercise the claimed production capability.
- **Tier F (Architectural Incompatibility)**: System architecture fundamentally does not support the claimed feature (e.g. zero-downtime rotation with single-key JWT).
- **Tier G (Absent Enforcement / Insecure Implementation)**: Code directly contradicts the claimed security standard (e.g. unauthenticated routes, `localStorage` tokens, hardcoded delays).

---

## 2. Test Classification Table

| Tier | Count | Percentage | Dimensions Assigned |
| :--- | :---: | :---: | :--- |
| **Tier A (Runtime Executable)** | 18 | 42.9% | SEC-02, SEC-03, SEC-04, SEC-07, SEC-08, SEC-09, SEC-11, DUR-02, GOV-02, OBS-01, OBS-02, OBS-03, OBS-04, PERF-02, ML-04, ML-05, OPS-01, OPS-02, OPS-03, OPS-05, OPS-06, UI-02 |
| **Tier B (Valid Integration Test)** | 6 | 14.3% | SEC-05, SEC-06, DUR-04, DUR-05, DUR-06, GOV-03, RT-01, OPS-04 |
| **Tier C (Static Analysis)** | 2 | 4.8% | DUR-03, GOV-01 |
| **Tier D (Doc Only)** | 0 | 0.0% | None (all claims had some test or code) |
| **Tier E (Flawed Test)** | 7 | 16.7% | DUR-01, PERF-01, PERF-03, ML-01, ML-02, ML-03 |
| **Tier F (Architectural Incompatibility)** | 1 | 2.4% | SEC-10 |
| **Tier G (Absent Enforcement)** | 8 | 19.0% | SEC-01, RT-02, UI-01 |

---

## 3. Analysis of Flawed Tests (Tier E)

1. **`tests/ingestion/test_load_500eps.py` (DUR-01, PERF-01)**:
   - **Flaw**: Utilized `fakeredis.FakeRedis()`.
   - **Impact**: Masked the fact that synchronous Redis calls block the single-threaded Uvicorn asyncio event loop under real TCP socket load.
2. **`tests/ml/test_walk_forward_benchmark.py` (ML-01, ML-02)**:
   - **Flaw**: Generated 1,500 random numbers with `np.random.seed(42)` and fitted a temporary model in memory.
   - **Impact**: Masked the fact that the actual production model in `ml_models/registry/` has 0.0 metrics, and `AnomalyDetector` achieves only 14.5% recall on real honeypot data.
3. **`tests/ml/test_adversarial.py` (ML-03)**:
   - **Flaw**: Hardcoded `is_malicious=True` in test input, triggering `if context.is_malicious: return CRITICAL`.
   - **Impact**: Masked the fact that mutated exploit payloads easily evade detection when the bypass flag is omitted.
4. **`tests/test_pitr_recovery.py` (GOV-02)**:
   - **Flaw**: Performed regex searches on shell script text without executing a backup or restore.
   - **Impact**: Masked the fact that `/var/lib/postgresql/archive` was owned by root and throwing continuous `Permission denied` errors.
