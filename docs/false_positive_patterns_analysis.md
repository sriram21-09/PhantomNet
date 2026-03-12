# False Positive Patterns Analysis

## Overview
This document analyzes 126 false positive cases identified during the validation of the anomaly detection model (Week 11 Day 3).

## Identified Patterns

### 1. Internal Infrastructure Traffic
- **Pattern**: Significant number of false positives originate from the `192.168.1.0/24` subnet.
- **Root Cause**: The model perceives normal internal administrative or cross-service communication as anomalous because it deviates slightly from the baseline of "quiet" honeypot traffic.
- **Example IPs**: `192.168.1.18`, `192.168.1.14`, `192.168.1.24`.

### 2. Standard Web & Management Traffic
- **Pattern**: Traffic on ports `80` (HTTP), `443` (HTTPS), and `22` (SSH) from internal sources is frequently flagged.
- **Root Cause**: These are common ports, but in a honeypot context, even benign connections to these ports can trigger high anomaly scores if not correctly filtered.

### 3. Protocol Variations
- **Pattern**: `UDP` traffic from known internal sources is often misclassified.
- **Root Cause**: UDP traffic patterns can be more erratic than TCP, leading to higher sensitivity in the anomaly detection algorithm.

### 4. Anomaly Score Thresholding
- **Pattern**: Many false positives have anomaly scores very close to the decision threshold (e.g., between -0.01 and -0.1).
- **Root Cause**: The current decision threshold is too aggressive, catching near-normal events that are not actually malicious.

## Recommended Mitigation Strategies

1. **IP Whitelisting**: Implementation of a whitelist for known-good internal CIDR ranges (e.g., `192.168.1.0/24`).
2. **Threshold Tuning**: Adjust the anomaly detection threshold to be less sensitive to near-zero scores.
3. **Time-Based Context**: Implement logic to ignore certain types of "busy" traffic during known maintenance windows or high-activity periods.
4. **Service-Based Whitelisting**: Exclude specific protocol/port combinations that are known to be used by internal management services.
