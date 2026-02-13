# False Positive Analysis

## Overview
Analysis of misclassified events from `data/predictions.csv` generated on 2026-02-12.

| Metric | Count |
| :--- | :--- |
| **False Positives (FP)** | **30** |
| **False Negatives (FN)** | **0** |
| **Total Misclassifications** | **30** |

## 1. False Positive Investigation
**Definition**: Benign traffic misclassified as Malicious.

### Patterns Observed
Upon reviewing `data/predictions.csv`, several Benign events were marked as MALICIOUS (Anomaly Score < 0).

**Example FPs:**
- `192.168.1.24` (TCP/80) - Score: -0.057
- `192.168.1.14` (TCP/22) - Score: -0.030
- `192.168.1.34` (TCP/443) - Score: -0.008

### Root Cause Analysis
- **Traffic Spikes**: The model seems sensitive to bursty traffic even from internal IPs.
- **Protocol/Port Combinations**: Standard HTTP/HTTPS/SSH traffic from specific internal IPs (`192.168.1.x`) is occasionally flagged. This suggests the "normal" training data (extracted from the same batch) might have had high variance, or the `contamination` parameter (set to auto/0.1 in `AnomalyDetector`) is forcing ~10% of data to be outliers regardless of actual nature.
- **Model Behavior**: Isolation Forest with `contamination=0.1` will *always* flag the top 10% most anomalous-looking data points as anomalies, even if they are benign.

## 2. False Negative Investigation
**Definition**: Malicious traffic misclassified as Benign.

### Patterns Observed
- **Zero False Negatives**.
- All simulated attacks (DDoS, Port Scans, SQLi) were correctly identified.

### Conclusion
- The model is **highly sensitive** (Recall = 1.00), capturing all threats.
- However, it is **over-aggressive** (Precision = 0.69), flagging legitimate traffic as malicious.

## 3. Recommendations
1. **Adjust Contamination**: The hardcoded `contamination=0.1` in `AnomalyDetector` is likely too high for a clean network. Recommendation: Lower to `0.05` or `0.01` if false positives persist.
2. **Feature Engineering**: `session_duration_estimate` and `packet_size_variance` might be noisy for short-lived normal connections.
3. **Allowlisting**: Consider allowlisting known admin IPs (e.g., `192.168.1.24`) to reduce FPs.
