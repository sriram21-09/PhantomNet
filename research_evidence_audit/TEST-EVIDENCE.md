# PhantomNet Test Suite Evidence

## 1. Test Suite Distribution
The PhantomNet codebase contains **176 project-specific test files** (excluding virtual environments and third-party packages):

| Category | File Count | Scope |
|---|---:|---|
| Backend Core Tests (ackend/tests/) | 26 | Database operations, API routes, honeypot handlers |
| Backend ML Tests (ackend/tests/ml/) | 5 | Feature extraction, scoring models, and thresholds |
| Sentinel Tests (ackend/tests/sentinel/) | 3 | Playbooks, confidence scoring, and SOAR logic |
| System & API Tests (	ests/, 	ests/api/) | 71 | Endpoints, TAXII 2.1 protocol, authentication |
| Integration & Load Tests (	ests/integration/, load/) | 8 | Concurrency, SQLite contention, burst handling |
| Resilience Tests (	ests/resilience/) | 4 | Service failure, database reconnection, recovery |
| UI & E2E Tests (rontend-dev/.../tests/e2e/) | 3 | Dashboard rendering and frontend telemetry |
| Remediation & Audit Scripts (udit/, scripts/) | 56 | Verification, publication validation, fixes |

## 2. Execution Findings
- Unit and micro-integration tests demonstrate high passing rates across all protocol handlers and threat intelligence generation routines.
- End-to-end autonomous integration tests fail due to the unscaled DBSCAN clustering issue, but pass 100% when StandardScaler remediation is applied.
