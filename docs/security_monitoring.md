# Security Monitoring System

PhantomNet includes a comprehensive security monitoring system designed to detect, correlate, and alert on suspicious network activities.

## Architecture

The system consists of three main components:

1.  **AlertManager**: Centralized service for creating and managing security alerts.
2.  **CorrelationEngine**: Analyzes event patterns to identify complex attack scenarios.
3.  **BaselineMonitor**: Tracks steady-state traffic and detects anomalous spikes.

### 1. Alert Manager (`alert_manager.py`)
Provides a unified API for generating alerts. It includes built-in **deduplication** to prevent alert fatigue. If a similar alert (same type and source IP) occurs within a configurable window (default 5 minutes), it is suppressed.

### 2. Correlation Engine (`correlation_engine.py`)
Runs as a background service and performs the following checks:
-   **Multi-Protocol Detection**: Alerts if a single source IP accesses more than 2 distinct protocols (e.g., SSH, HTTP, and FTP) within 5 minutes.
-   **High-Frequency Detection**: Alerts if a source IP generates more than 50 events within 5 minutes.

### 3. Baseline Monitor (`baseline_monitor.py`)
Statistically analyzes traffic volume:
-   Establishes a baseline (events per minute).
-   Detects spikes exceeding 5x the baseline (minimum 20 events/min).
-   Automatically adjusts the baseline over time to account for normal traffic drift.

## Database Schema

Alerts are stored in the `alerts` table with the following fields:
-   `timestamp`: When the alert was generated.
-   `level`: Severity (INFO, WARNING, CRITICAL).
-   `type`: Category (CORRELATION, BASELINE, INTRUSION).
-   `source_ip`: The IP address responsible for the alert.
-   `description`: Human-readable summary.
-   `details`: JSON-formatted technical data.

## Verification

Automation tests are available in `backend/tests/test_security_monitoring.py`. Run them with:
```bash
python backend/tests/test_security_monitoring.py
```
