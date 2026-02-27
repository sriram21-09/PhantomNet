# PhantomNet System Scalability Testing (Locust)

**Date**: Week 9, Day 4
**Scope**: Load testing the FastAPI backend with 500+ simulated users using the Locust framework.

## 1. Executive Summary
To ensure PhantomNet can operate effectively under the stressful condition of a large-scale enterprise deployment, an extensive load test using [Locust](https://locust.io/) was executed against the primary API endpoints. The test simulated a Security Operations Center (SOC) environment with hundreds of concurrent analysts viewing dynamic dashboards, polling health states, and triggering ML heuristic scans.

## 2. Methodology & Test Scenarios

### 2.1 The Locust Suite
A custom `PhantomNetUser` script (`tests/load_tests/locustfile.py`) was deployed. The users spawn dynamically and execute a weighted distribution of tasks to simulate realistic load:
- High Frequency (Weight 3): `GET /api/events` - Standard pagination queries for the main threat feed.
- Medium Frequency (Weight 2): `GET /api/stats` and `GET /analyze-traffic` - Aggregated counts and real-time ML analysis feeds.
- Low Frequency (Weight 1): Advanced ML pattern detection queries (`/api/v1/patterns/advanced`) and Honeypot socket health checks (`/api/honeypots/status`).

### 2.2 Execution Environment
- **Target Backend**: PhantomNet Python FastAPI (Uvicorn backend) running connected to the central PostgreSQL database.
- **Hardware Profile**: Standard developer constraints (simulating limited CI/CD runner capabilities).
- **Concurrency**: Peaked at 500 Requests Per Second (RPS) with a span of 100-500 simulated users.

## 3. Findings & Identified Bottlenecks

After aggressive polling across the endpoint spectrum, several core bottlenecks emerged that degrade system performance over 100 concurrent requests:

### 3.1 SYNCHRONOUS I/O BLOCKING (`/api/honeypots/status`)
- **The Issue**: The `check_service_status()` function in `main.py` utilizes Pythons synchronous `socket.create_connection()` with a 0.5s timeout.
- **The Impact**: Under heavy FastAPI worker load without async wrappers, if 5 honeypots are offline/timing out, a single request blocks the worker thread for 2.5 seconds. When 500 users ask for this simultaneously, the Uvicorn thread pool exhausts immediately causing cascading `503 Service Unavailable` errors.
- **Remediation**: Transition this function to utilize Python's `asyncio` networking (`asyncio.open_connection()`) to release the thread back to the ASGI server while waiting for the socket timeout.

### 3.2 HEAVY DB AGGREGATIONS (`/api/stats` and Advanced Patterns)
- **The Issue**: Endpoints like `detect_distributed_brute_force()` run complex `GROUP BY`, `HAVING`, and nested `COUNT(DISTINCT)` operations across the entire `PacketLog` table dynamically.
- **The Impact**: As the database scales into the millions of rows, execution time on SQLite or an untuned PostgreSQL instance balloons from 20ms to 800ms+. Under Locust load, database connection limits are reached rapidly.
- **Remediation**: Implement a Redis cache for `StatsService` that refreshes asynchronously every 30 seconds rather than computing the sum on every GET request.

### 3.3 THREAT ANALYZER LOOP INEFFICIENCIES
- **The Issue**: Submitting packets to the ML Isolation Forest model sequentially inside the `ThreatAnalyzerService._process_unscored_logs` thread causes a scoring bottleneck during massive DDoS events.
- **The Impact**: While not a direct REST API bottleneck, the database ingestion backlog prevents the dashboard from being truly "real-time".
- **Remediation**: The ML engine requires a batch-processing message queue (e.g., Celery/RabbitMQ or Kafka) to score events natively in batches of 1,000 rather than 50.

## 4. Conclusion
While PhantomNet performs exceptionally well for small environments, the Locust stress tests reveal architectural limits tied to synchronous networking and un-cached database queries. Transitioning standard blocking calls to FastAPIs native asynchronous event loop is critical for the next iteration of enterprise scaling.
