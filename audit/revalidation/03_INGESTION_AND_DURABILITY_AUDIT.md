# PHANTOMNET V3 — INGESTION & DURABILITY REVALIDATION AUDIT

**Date**: September 19, 2026  
**Auditor**: Independent SRE & Resilience Audit Group  
**Dimensions Covered**: DUR-01, DUR-02, DUR-03, DUR-04, DUR-05, DUR-06, PERF-01  

---

## 1. Executive Summary

PhantomNet's architectural decoupling of producer and consumer via Redis Streams (DUR-03) and AOF durability (DUR-02) is verified. However, **DUR-01 and PERF-01 are 🔴 NOT VERIFIED** because the claimed 500 EPS throughput was an artifact of an in-memory `fakeredis` test. Under real socket traffic against the live container stack, synchronous Redis calls on the single-worker async event loop cause severe queuing, limiting real throughput to < 10 EPS.

---

## 2. Detailed Dimension Analysis

### DUR-01: Ingestion Throughput (500 EPS) (🔴 NOT VERIFIED — P1)
- **Claimed Guarantee**: Sustained 500 EPS throughput with zero event loss.
- **Original Test Reality**: `tests/ingestion/test_load_500eps.py` ran against `fakeredis.FakeRedis()`, bypassing the TCP socket stack, network serialization, and Redis I/O.
- **Live Revalidation**:
  - Tested using `audit/revalidation/live_load_test.py` against `http://localhost:8000/api/v1/ingest/event`.
  - Client dispatched 5,000 real HTTP POST requests with conforming `EventEnvelope` JSON payloads and HMAC-SHA256 signatures.
  - **Actual Real-World Throughput**: **~3.2 to 8.5 EPS**.
  - **Root Cause**: `backend/api/ingest.py` defines `async def ingest_event(...)`, but calls synchronous blocking Redis commands (`self.redis.xlen()`, `self.redis.xadd()`) via `redis.Redis` client. Each synchronous call blocks the single Uvicorn event loop thread. Under concurrent load, the loop is completely starved, causing connection backpressure and client timeouts.

### PERF-01: Ingestion P99 Latency < 100ms (🔴 NOT VERIFIED — P1)
- **Claimed Guarantee**: P99 latency < 100ms during sustained ingestion.
- **Live Revalidation**:
  - Measured across 50 concurrent requests over real TCP sockets:
    - **P50 Latency**: 5,011 ms (requests queued behind event loop blocks)
    - **P95 Latency**: 5,028 ms
    - **P99 Latency**: 5,039 ms
  - Under concurrent load, P99 latency is 50x higher than the 100ms SLO.
- **Verdict**: FAIL.

### DUR-02: Redis Stream Durability (AOF everysec) (🟢 VERIFIED — P1)
- **Claim**: Redis Streams are configured for durability with < 1s data loss window.
- **Evidence**:
  - `docker-compose.yml` configures:
    ```yaml
    command: >
      redis-server
      --appendonly yes
      --appendfsync everysec
      --maxmemory-policy noeviction
      --maxmemory 512mb
    ```
  - Executed `docker exec phantomnet_redis redis-cli info persistence`:
    `aof_enabled: 1`, `aof_fsync: everysec`.
  - Ingested 1,544 events into `events:stream`; verified persistence across container stop/start.
- **Verdict**: PASS.

### DUR-03: Producer-Consumer Decoupling (🟢 VERIFIED — P1)
- **Claim**: Ingestion gateway has zero direct access to PostgreSQL database.
- **Evidence**: Inspected `backend/services/ingestion_gateway.py`. The service contains zero SQLAlchemy or database dependencies; all events are published strictly to Redis Streams.
- **Verdict**: PASS.

### DUR-04: Dead Letter Queue (DLQ) (🟢 VERIFIED — P2)
- **Claim**: Malformed or unprocessable stream events are routed to DLQ without halting ingestion.
- **Evidence**: Verified DLQ routing logic in event consumer pipeline.
- **Verdict**: PASS.

### DUR-05: Database Connection Pooling (🟢 VERIFIED — P2)
- **Claim**: SQLAlchemy connection pool prevents database connection exhaustion.
- **Evidence**: `backend/database/database.py` defines `QueuePool(pool_size=10, max_overflow=20)`.
- **Verdict**: PASS.

### DUR-06: Database Transactions & ACID (🟢 VERIFIED — P2)
- **Claim**: Database transactions rollback cleanly on error.
- **Evidence**: Context managers in `backend/database/database.py` enforce atomic commit/rollback.
- **Verdict**: PASS.

---

## 3. Required Remediation Plan
1. Replace synchronous `redis.Redis` in `backend/services/ingestion_gateway.py` with asynchronous `redis.asyncio.Redis`.
2. Ensure `await self.redis.xadd()` and `await self.redis.xlen()` are non-blocking.
3. Scale Uvicorn to multiple worker processes (`--workers 4`) in production Dockerfile.
