# PhantomNet Verification Test Plan – Week 4

## Scope
Validate correctness, consistency, and stability of PhantomNet’s detection pipeline.

---

## Test Environment

- OS: Windows
- Backend: FastAPI + Uvicorn
- Database: PostgreSQL
- Frontend: React (Vite)
- Network: Live traffic capture via Scapy

---

## Test Categories

### 1. Functional Tests

| Test | Expected Result |
|----|----|
| Start backend | No errors |
| Sniffer startup | Background thread active |
| Packet capture | New PacketLog rows |
| Threat detection | Correct classification |
| Events API | JSON response with DB data |

---

### 2. Data Integrity Tests

| Test | Expected Result |
|----|----|
| DB insert | No null critical fields |
| Timestamp accuracy | UTC consistency |
| Threat consistency | Matches attack_type |
| No duplicate rows | One packet = one event |

---

### 3. Frontend Integration Tests

| Test | Expected Result |
|----|----|
| Events page | No mock data |
| Filters | Correctly narrow results |
| Pagination | Stable navigation |
| Large dataset | No UI freeze |

---

### 4. Negative Tests

| Test | Expected Result |
|----|----|
| DB unavailable | Graceful API failure |
| Empty logs | UI shows empty state |
| Invalid filter | API returns safely |

---

## Exit Criteria

- All functional tests pass
- No data mismatch between UI and DB
- No uncaught exceptions in backend
