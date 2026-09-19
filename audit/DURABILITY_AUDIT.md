# PHANTOMNET V3 — DATA PIPELINE & DURABILITY AUDIT REPORT (DUR-01 TO DUR-07)

**Audit Date**: September 19, 2026  
**Auditors**: Site Reliability & Database Engineering Group  
**Target Git SHA**: `8c199f2877901773b1beb04f80e244f98d0f7e3f`  
**Claimed Status**: 7 / 7 Verified (100%)  
**Audited Status**: **3 Verified (42.9%)**, **3 Partially Verified (42.9%)**, **1 Not Verified (14.3%)**

---

## 1. Domain Summary & Scorecard

| Dimension ID | Dimension Name | Claimed Status | Audited Status | Risk Level | Evidence Level | Verdict |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **DUR-01** | Ingestion Sustained 500 EPS | VERIFIED | 🔴 **NOT VERIFIED** | **P1 (High)** | Level 2 (Flawed Test) | Test runs on `fakeredis` and in-memory SQLite in 1.07s on a single thread. Zero real network socket or disk I/O tested. |
| **DUR-02** | Peak 2,000 EPS Headroom | VERIFIED | 🟡 **PARTIALLY VERIFIED** | P2 (Medium) | Level 2 (Flawed Test) | Tested against in-memory fake queue only. Real Redis Stream memory and network buffers unverified. |
| **DUR-03** | Zero Event Loss (Redis AOF) | VERIFIED | 🟡 **PARTIALLY VERIFIED** | P2 (Medium) | Level 3 (Static Config) | Redis AOF configuration verified in `docker-compose.yml`. However, crash recovery test uses mocked process. |
| **DUR-04** | Dead Letter Queue (DLQ) | VERIFIED | 🟢 **VERIFIED** | P2 (Medium) | Level 2 (Test) / Level 3 (Static) | `dead_letter_events` table captures poisoned payloads after 3 failed retries. |
| **DUR-05** | Database Connection Pooling | VERIFIED | 🟢 **VERIFIED** | P2 (Medium) | Level 3 (Static) | SQLAlchemy `QueuePool` configured with `pool_size=20`, `max_overflow=10`, `pool_pre_ping=True`. |
| **DUR-06** | Database Transactional Integrity | VERIFIED | 🟢 **VERIFIED** | P1 (High) | Level 2 (Test) / Level 3 (Static) | Atomic transactions wrapped in context managers with rollback on database exceptions. |
| **DUR-07** | Redis Backpressure & Memory Caps | VERIFIED | 🟡 **PARTIALLY VERIFIED** | P2 (Medium) | Level 3 (Static Config) | `--maxmemory 512mb` and `noeviction` present in Compose. Saturation rejection tested via mock. |

---

## 2. In-Depth Analysis by Dimension

### DUR-01: Ingestion Sustained 500 EPS (🔴 NOT VERIFIED — P1)
- **Documented Claim**: "Sustains 500 events/second for 10 consecutive seconds with zero event loss and P99 latency < 100ms."
- **Flawed Testing Methodology**:
  - `tests/load_tests/test_sustained_500eps.py` is cited as proof.
  - Line 24: Imports `fakeredis.FakeStrictRedis()`.
  - Line 28: Uses `sqlite:///:memory:` as the test database engine.
  - When executed, the test processes 5,000 events in **1.07 seconds on a single CPU thread**.
- **Why This Test Fails to Prove Production Readiness**:
  - In a real deployment, 500 EPS involves:
    1. 500 incoming TCP connections per second over HTTP/1.1 or HTTP/2.
    2. JSON parsing and Pydantic validation across worker processes.
    3. Network socket writes to Redis Stream (`XADD`).
    4. Async consumer worker dequeuing (`XREADGROUP`).
    5. Disk I/O flushing to PostgreSQL WAL and Redis AOF (`appendfsync everysec`).
  - By replacing the network and disk with Python in-memory dictionaries (`fakeredis` and RAM SQLite), the test measures nothing more than local CPU memory bandwidth.
- **Evidence**: `audit/logs/dur_01_sustained_500eps.log`.

### DUR-02: Peak 2,000 EPS Headroom (🟡 PARTIALLY VERIFIED)
- **Documented Claim**: "Handles 4x burst traffic (2,000 EPS) for 3 seconds without buffer overflow."
- **Audit Finding**:
  - `tests/load_tests/test_peak_2000eps.py` similarly executes against an in-memory queue.
  - While the queuing logic correctly enqueues items, real-world OS network buffer limits (`somaxconn`, `net.ipv4.tcp_max_syn_backlog`), Redis socket buffers, and Uvicorn backlog limits are never engaged.
- **Evidence**: `audit/logs/dur_02_peak_2000eps.log`.

### DUR-03: Zero Event Loss / Redis AOF Persistence (🟡 PARTIALLY VERIFIED)
- **Documented Claim**: "Zero event loss during unexpected container restart due to AOF fsync=everysec."
- **Audit Finding**:
  - `docker-compose.yml` lines 40-42 correctly configure:
    ```yaml
    command: >
      redis-server
      --appendonly yes
      --appendfsync everysec
      --maxmemory-policy noeviction
      --maxmemory 512mb
    ```
  - However, the crash recovery test in `tests/durability/test_redis_aof.py` does not terminate a running Redis container with `kill -9` and inspect data recovery. Instead, it mocks the Redis client object and simulates persistence state in memory.
- **Evidence**: `audit/logs/dur_03_zero_event_loss.log`.

### DUR-04: Dead Letter Queue (DLQ) (🟢 VERIFIED)
- **Documented Claim**: "Poison-pill events failing processing 3 times are moved to Dead Letter Queue without stalling ingestion."
- **Audit Finding**:
  - `backend/database/models.py` defines `DeadLetterEvent` table with columns: `id`, `original_payload`, `error_message`, `retry_count`, `created_at`.
  - Ingestion pipeline catches unparseable or schema-violating events after 3 retries, writes them to `DeadLetterEvent`, and logs a warning while continuing stream consumption.
- **Evidence**: `audit/logs/dur_04_dead_letter_queue.log`.

### DUR-05: Database Connection Pooling (🟢 VERIFIED)
- **Documented Claim**: "Database connection pool maintains healthy connections and recycles stale connections."
- **Audit Finding**:
  - `backend/database/session.py` configures SQLAlchemy engine with:
    - `poolclass=QueuePool`
    - `pool_size=20`
    - `max_overflow=10`
    - `pool_pre_ping=True` (validates connection liveness before checkout)
    - `pool_recycle=3600` (recycles connections older than 1 hour)
- **Evidence**: `audit/logs/dur_05_db_connection_pooling.log`.

### DUR-06: Database Transactional Integrity (🟢 VERIFIED)
- **Documented Claim**: "Multi-step database updates are atomic; partial failures trigger automatic rollback."
- **Audit Finding**:
  - Database operations are wrapped in `with get_db() as db:` context managers.
  - Exceptions during multi-table writes (e.g. creating an Alert and updating an Incident simultaneously) trigger `db.rollback()`, leaving no orphaned rows.
- **Evidence**: `audit/logs/dur_06_db_transactional_integrity.log`.

### DUR-07: Redis Backpressure & Memory Caps (🟡 PARTIALLY VERIFIED)
- **Documented Claim**: "Redis enforces 512MB memory cap with noeviction policy, applying backpressure to upstream producers."
- **Audit Finding**:
  - Configuration in `docker-compose.yml` sets `--maxmemory 512mb` and `--maxmemory-policy noeviction`.
  - However, the producer response to `OOM command not allowed when used memory > 'maxmemory'` in `backend/api/ingestion.py` was tested using a simulated mock exception rather than saturating a live Redis instance.
- **Evidence**: `audit/logs/dur_07_redis_backpressure.log`.

---

## 3. Remediation Roadmap

1. **[P1] DUR-01 & DUR-02**: Develop a real Locust or k6 load test script (`tests/load_tests/locustfile.py`) that generates 500 HTTP requests per second over network sockets against the running `phantomnet_api` Docker container with live PostgreSQL and Redis.
2. **[P2] DUR-03**: Implement an integration test using `testcontainers` or Docker CLI that writes 1,000 events to a live Redis container, executes `docker kill -s 9 phantomnet_redis`, restarts the container, and verifies that all events survive via AOF.
3. **[P2] DUR-07**: Verify upstream HTTP 429 / 503 backpressure response headers when Redis returns `OOM` errors during live load.
