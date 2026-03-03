# PhantomNet — Performance Benchmarking Methodology

**Document Version**: 1.0
**Target Audience**: Security Engineers, QA, and Performance Testers

## 1. Overview

This document outlines the standardized methodology for evaluating the performance, scalability, and detection accuracy of the PhantomNet Distributed Honeypot Mesh. All major releases must be validated against this methodology before moving to production.

---

## 2. Benchmark Metrics & Targets

Performance is evaluated across six core dimensions:

| Category | Metric | Definition | Minimum Target |
|----------|--------|------------|----------------|
| **Accuracy** | True Positive Rate (TPR) | % of actual attacks correctly classified as threats | **> 90%** |
| | False Positive Rate (FPR) | % of benign traffic falsely classified as threats | **< 5%** |
| **Speed** | Detection Latency | Time from network packet to database alert generation | **< 2.0s** |
| | ML Inference Time | Time to score a single batch of events (up to 1,000) | **< 50ms** |
| **Scale** | Maximum Throughput | Sustainable event ingestion rate without dropping packets | **> 1,000 events/sec** |
| | API Responsiveness (P95) | 95th percentile latency for SOC dashboard queries | **< 100ms** |
| **Efficiency** | CPU per node | Compute overhead of a single simulated honeypot | **< 0.5 cores** |
| | Memory per node | RAM overhead of a single simulated honeypot | **< 512 MB** |

---

## 3. Test Scenarios

### Scenario A: Baseline Profiling (Accuracy & Latency)
- **Goal**: Validate ML accuracy and base detection latency.
- **Dataset**: `data/ground_truth.csv` (Mixed benign/malicious PCAP replay).
- **Execution**: Run the `scripts/validate_model.py` test suite.
- **Measurement**: Scikit-learn classification report (Precision, Recall, F1) and `time.time()` latency deltas.

### Scenario B: High Volume Load (Throughput)
- **Goal**: Measure max ingestion rate and DB write performance.
- **Execution**: Generate 10,000 synthetic events and inject via SQLAlchemy bulk inserts over 10 minutes (1,000 events/min).
- **Measurement**: Verify 0% data loss, measure CPU using `psutil`, and record API P95 latency during the ingestion spike.

### Scenario C: Sustained Operation (Memory Leaks)
- **Goal**: Identify slow memory leaks and database bloat.
- **Execution**: Sustained feed of 500 events/min for 4 hours.
- **Measurement**: `htop` / Docker stats memory tracking at T+0, T+1h, T+2h, T+4h.

### Scenario D: DDoS Burst (Recovery)
- **Goal**: Test queue behavior under extreme conditions.
- **Execution**: 5,000 events generated and submitted within 60 seconds.
- **Measurement**: Time to clear backlog (recovery time), queue peak size, and CPU max utilization.

### Scenario E: API Scalability (Concurrent Users)
- **Goal**: Validate UI/SOC dashboard responsiveness.
- **Execution**: Locust load test targeting REST API endpoints.
- **Users**: 100 to 500 concurrent users.
- **Ramp-up**: 10 users per second.

---

## 4. Load Generation Tools

### 4.1 Locust (API Testing)

**Requirements**: Extract `locustfile.py` to `tests/load_tests/`.

```bash
# Install Locust
pip install locust

# Run Headless Test (500 users, 10/sec spawn rate, 5 mins)
locust -f tests/load_tests/locustfile.py --headless -u 500 -r 10 --run-time 5m --host=http://localhost:8000
```

### 4.2 Network Traffic Gen (Honeypot Load)

**Requirements**: Use Mininet topology + `ncat`.

```bash
# In Mininet CLI (from attacker node h6)
mininet> h6 ./scripts/generate_traffic.sh 10.0.0.1 2222 1000
```

*The shell script should spawn 1,000 concurrent simple TCP connections and immediately drop them to simulate a massive port scan.*

---

## 5. Resource Monitoring

All performance tests MUST be accompanied by resource monitoring.

**Docker Services**:
```bash
docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
```

**Host System (Python)**:
Use `psutil` within test scripts to log point-in-time metrics:
```python
import psutil

def log_resources():
    print(f"CPU: {psutil.cpu_percent()}%")
    print(f"Memory: {psutil.virtual_memory().used / (1024**2):.2f} MB")
```

---

## 6. Reporting Standard

All benchmark results must be documented in `reports/` using the following naming convention:
`reports/performance_[test_type]_week[X]_day[Y].md`

The report must containing:
1. Executive Summary (Pass/Fail)
2. Test Environment (Specs)
3. Raw Metrics Table (Current vs Target)
4. Identified Bottlenecks (Prioritized P0, P1, P2) 
5. Remediation Plan

*(See `reports/baseline_performance_week10_day3.md` for a reference template)*
