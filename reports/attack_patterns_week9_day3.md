# Attack Pattern Detection

**Date**: Week 9, Day 3
**Scope**: Advanced Heuristic Pattern Detection Algorithms & API Integration

## 1. Executive Summary
The PhantomNet Detection Engine has been upgraded to intercept sophisticated threats that typically evade standard per-packet anomaly detection thresholds. A new `AdvancedPatternDetector` module actively hunts for coordinated activity across time slices, focusing initially on Distributed Brute Force campaigns and "Low and Slow" reconnaissance scanning.

## 2. Implemented Detection Algorithms

### 2.1 Distributed Brute Force Detection
- **Mechanism:** Analyzes the `PacketLog` database over a 15-minute sliding window to identify when a single destination (e.g., Honeypot port 2222) is repeatedly accessed by multiple distinct source IPs.
- **Thresholds:** Detects activity exceeding 20 total attempts originating from at least 3 distinct IP addresses.
- **Security Logic:** Bots and C2 networks distribute password guessing across hundreds of nodes to prevent any single node from tripping a rate limit. By aggregating attempts by destination rather than source, the detector flags the coordinated campaign.

### 2.2 "Low and Slow" Scan Detection
- **Mechanism:** Analyzes traffic over an extended 24-hour sliding window.
- **Thresholds:** Flags any source IP communicating with more than 50 distinct destination ports *while* maintaining an average connection rate of fewer than 2.0 events per minute.
- **Security Logic:** Standard port scans trigger immediate alarms by aggressively mapping thousands of ports per second. "Low and Slow" sweeps evade these systems entirely. By taking a 24-hour historical view, the detector exposes the hidden reconnaissance activity.

## 3. Real-Time Pipeline Integration

### The Threat Analyzer Service
The `ThreatAnalyzerService` background thread has been modified. Alongside its primary function of scoring individual unscored packets via the ML model, it now runs a secondary loop triggered every 60 seconds:

1. **Invoke `run_all_checks()`**: The thread instantiates the `AdvancedPatternDetector`.
2. **Detection Processing**: The detector scans the database using the algorithms outlined above.
3. **Alert Generation**: If an advanced threat is found:
   - It is actively logged to the backend console as an `ADVANCED THREAT DETECTED` warning.
   - It triggers a WebSocket push (`ADVANCED_THREAT_DETECTED`) to instantaneously alert the frontend UI dashboard.

## 4. Analytics API

A dedicated API router has been created at `backend/api/pattern_analytics.py` to allow the dashboard to poll current patterns on-demand.

- **Endpoint:** `GET /api/v1/patterns/advanced`
- **Response Format:**
```json
{
  "timestamp": "2026-02-26T17:55:00.000Z",
  "distributed_brute_force_ssh": [
    {
      "target_ip": "10.0.2.31",
      "target_port": 2222,
      "distinct_attacker_ips": 14,
      "total_attempts": 342,
      "pattern": "Distributed Brute Force"
    }
  ],
  "low_and_slow_scans": []
}
```

## 5. Next Steps
Future iterations will introduce:
1. **Beaconing Detection:** Heuristics to identify perfectly periodic intervals of communication standard in C2 implant callbacks.
2. **Temporal ML:** Supplying these time-series pattern insights directly back into the core Machine Learning Model as synthesized features.
