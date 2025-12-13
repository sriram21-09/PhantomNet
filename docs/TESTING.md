
# PhantomNet Testing – Day 7

This document lists manual test cases to verify that PhantomNet is working end-to-end: honeypots, log ingestion, database, and dashboard.

---

## 1. Prerequisites

Before testing:

- Complete all steps in `docs/SETUP.md`
- Backend API running on http://localhost:8000
- Frontend running on http://localhost:5173
- Database `phantomnet` reachable

---

## 2. SSH Honeypot Test

**Goal:** Confirm SSH honeypot captures connection attempts and logs them.

1. From another terminal, attempt an SSH connection:

```bash
ssh testuser@localhost -p 2222
````

2. Enter any password (it should fail or behave like a fake SSH).

3. Verify:

* A new log entry was written (file or DB, depending on implementation)
* If logs are stored in DB, run:

```sql
SELECT * FROM events
WHERE honeypot_type = 'ssh'
ORDER BY timestamp DESC
LIMIT 5;
```

**Expected Result:**

* At least one new row appears with `honeypot_type = 'ssh'` and the source IP of your machine.

---

## 3. HTTP Honeypot Test

**Goal:** Confirm HTTP honeypot logs HTTP requests.

1. Send a request to the HTTP honeypot:

```bash
curl -v http://localhost:8080/test-path
```

2. Verify:

* Honeypot logs the request (path, method, IP)
* In DB (if applicable):

```sql
SELECT * FROM events
WHERE honeypot_type = 'http'
ORDER BY timestamp DESC
LIMIT 5;
```

**Expected Result:**

* New entry with `honeypot_type = 'http'`, including the path `/test-path`.

---

## 4. Log Ingestor / API Test

**Goal:** Verify the `/logs` API endpoint stores logs correctly.

1. Send a test log via API:

```bash
curl -X POST http://localhost:8000/api/logs \
-H "Content-Type: application/json" \
-d '{
  "source_ip": "10.0.0.5",
  "protocol": "SSH",
  "details": "Failed login attempt (manual test)"
}'
```

2. Verify response:

```json
{
  "message": "log stored successfully"
}
```

3. Check database:

```sql
SELECT * FROM events
WHERE src_ip = '10.0.0.5'
ORDER BY timestamp DESC
LIMIT 5;
```

**Expected Result:**

* A new row exists with `src_ip = '10.0.0.5'` and protocol / honeypot type set appropriately.

---

## 5. Database Connectivity Test

**Goal:** Ensure the backend can read/write from PostgreSQL.

1. From backend environment:

```bash
cd backend
source venv/bin/activate   # or venv\Scripts\activate on Windows
python
```

2. In Python shell:

```python
from db.connection import SessionLocal
from models.event_model import AttackEvent

db = SessionLocal()
count = db.query(AttackEvent).count()
print("Total events:", count)
db.close()
```

**Expected Result:**

* Prints `Total events: <number>` without errors.

---

## 6. Frontend Dashboard Test

**Goal:** Confirm the UI displays logs and does not crash.

1. Open the dashboard:

* [http://localhost:5173](http://localhost:5173)

2. Check:

* Stats or summary cards show values (or `0` without errors)
* Recent events table displays latest events
* Refresh page; no errors in browser console (F12 → Console)

3. Trigger new events (SSH / HTTP / API) and refresh dashboard.

**Expected Result:**

* New logs appear on the dashboard
* No crashes or blank pages

---

## 7. End-to-End Scenario

**Goal:** Validate full path: attacker → honeypot → log → DB → API → dashboard.

1. Perform SSH or HTTP test (Sections 2 or 3)
2. Confirm:

* Honeypot logs event
* Event appears in DB
* `/api/logs` or `/api/events` returns it
* Frontend displays the new log

**Expected Result:**

* A single attacker action produces a visible dashboard entry.

---

## 8. Recording Results

For each test:

* Mark as **PASS** or **FAIL**
* If FAIL:

  * Capture error messages
  * Note steps to reproduce
  * Create a GitHub Issue titled: `TEST FAIL: <area>`

Suggested tracking table:

| Test Case             | Status | Notes / Issue Link       |
| --------------------- | ------ | ------------------------ |
| SSH Honeypot Test     | PASS   |                          |
| HTTP Honeypot Test    | PASS   |                          |
| Log Ingestor Test     | FAIL   | Issue #12 – 500 on /logs |
| Database Connectivity | PASS   |                          |
| Frontend Dashboard    | PASS   |                          |
| End-to-End Scenario   | PASS   |                          |

---

## 9. Test Docs From Scratch (C4)

Each team member should:

1. Use a fresh machine or container
2. Follow `docs/SETUP.md` step-by-step
3. Execute all tests in `docs/TESTING.md`
4. Note missing steps or unclear instructions
5. Update documentation immediately to fix gaps

---

## 10. Final Documentation Commit (C5)

After verification:

```bash
git add docs/SETUP.md docs/TESTING.md
git commit -m "docs: add setup and testing guides"
git push origin <your-branch-name>
```

Create a pull request and merge into `main` after review.

```

If you want, I can next:
- Add **automated test placeholders**
- Convert this into **QA checklist format**
- Align it with **academic project evaluation rubrics**

Just say what’s next.
```
