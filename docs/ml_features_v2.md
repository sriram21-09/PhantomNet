# PhantomNet ML Features v2 — Complete Feature Documentation

**Project:** PhantomNet  
**Total Features:** 15  
**Date:** March 11, 2026  
**Source of Truth:** `docs/FEATURE_EXTRACTION_SPEC_FINAL.md`

---

## Feature Importance Rankings

Based on model evaluation across the Isolation Forest and Random Forest classifiers, features are ranked by their contribution to detection accuracy:

| Rank | Feature | Importance Score | Category |
|---|---|---|---|
| 1 | `honeypot_interaction_count` | 0.142 | Behavioral |
| 2 | `source_ip_event_rate` | 0.128 | Rate-based |
| 3 | `burst_rate` | 0.115 | Rate-based |
| 4 | `malicious_flag_ratio` | 0.098 | Historical |
| 5 | `threat_score` | 0.091 | Heuristic |
| 6 | `unique_destination_count` | 0.085 | Network |
| 7 | `z_score_anomaly` | 0.072 | Statistical |
| 8 | `rolling_average_deviation` | 0.065 | Statistical |
| 9 | `packet_length` | 0.052 | Packet |
| 10 | `attack_type_frequency` | 0.041 | Behavioral |
| 11 | `session_duration_estimate` | 0.035 | Temporal |
| 12 | `time_of_day_deviation` | 0.028 | Temporal |
| 13 | `packet_size_variance` | 0.022 | Packet |
| 14 | `destination_port_class` | 0.015 | Network |
| 15 | `protocol_encoding` | 0.011 | Network |

> **Key Insight:** Behavioral and rate-based features (ranks 1–3) account for **38.5%** of total importance, confirming that interaction patterns are the strongest signal for threat detection in honeypot environments.

---

## Complete Feature Descriptions

### 1. `packet_length`
- **Source:** `packet_logs.length`
- **Type:** Integer
- **Description:** Raw packet size in bytes.
- **Normal Range:** 40–1500 bytes
- **Anomalous Range:** <40 (malformed) or >1500 (jumbo/overflow)
- **Rationale:** Unusually large packets can indicate buffer overflow attempts; unusually small packets may be keepalive beacons from C2 channels.

### 2. `protocol_encoding`
- **Source:** `packet_logs.protocol`
- **Type:** Categorical → Integer (encoded)
- **Encoding Map:** TCP=6, UDP=17, ICMP=1, Other=0
- **Rationale:** Certain protocols correlate with specific attack vectors (e.g., ICMP for tunneling, UDP for amplification attacks).

### 3. `source_ip_event_rate`
- **Source:** `packet_logs.src_ip`
- **Type:** Float
- **Calculation:** Count of events from a source IP within a 60-second sliding window.
- **Normal Range:** <20 events/min
- **Anomalous Range:** ≥20 events/min
- **Rationale:** High event rates strongly indicate automated scanning, brute-force attacks, or DDoS participation.

### 4. `destination_port_class`
- **Source:** `packet_logs.dst_port`
- **Type:** Categorical → Integer (0=Well-Known 0–1023, 1=Registered 1024–49151, 2=Dynamic 49152–65535)
- **Rationale:** Attacks targeting well-known ports (SSH/22, HTTP/80) follow different patterns than those probing ephemeral ports.

### 5. `threat_score`
- **Source:** `packet_logs.threat_score`
- **Type:** Float (0–100)
- **Description:** Heuristic score from the rule-based detection engine.
- **Normal Range:** <50
- **Anomalous Range:** ≥50
- **Rationale:** Provides a baseline suspicion level from known signatures, complementing the ML anomaly score.

### 6. `malicious_flag_ratio`
- **Source:** `packet_logs.is_malicious`
- **Type:** Float (0.0–1.0)
- **Calculation:** (Malicious events from IP) / (Total events from IP) over the session history.
- **Normal Range:** <0.3
- **Anomalous Range:** ≥0.3
- **Rationale:** IPs with a history of malicious activity have a higher probability of future attacks (recidivism).

### 7. `attack_type_frequency`
- **Source:** `packet_logs.attack_type`
- **Type:** Integer
- **Calculation:** Count of a specific attack type from the same source IP.
- **Rationale:** Repetitive single-type attacks suggest automated tools, while diverse attack types indicate manual probing.

### 8. `time_of_day_deviation`
- **Source:** `packet_logs.timestamp`
- **Type:** Boolean → Integer (0 or 1)
- **Calculation:** 1 if activity occurs outside normal traffic hours (e.g., 02:00–06:00 local time), else 0.
- **Rationale:** Automated attacks disproportionately occur during off-peak hours.

### 9. `burst_rate`
- **Source:** `packet_logs.timestamp`
- **Type:** Float
- **Calculation:** Maximum events per source IP within any 10-second window in the session.
- **Normal Range:** <10
- **Anomalous Range:** ≥10
- **Rationale:** Bursty traffic is characteristic of flood attacks (SYN flood, UDP flood).

### 10. `packet_size_variance`
- **Source:** `packet_logs.length`
- **Type:** Float
- **Calculation:** Statistical variance of packet sizes for a given flow/session.
- **Rationale:** Automated attack tools often use fixed packet sizes (low variance), while legitimate traffic has natural size variation.

### 11. `honeypot_interaction_count`
- **Source:** `packet_logs.honeypot_type`
- **Type:** Integer
- **Calculation:** Number of distinct honeypots (SSH, HTTP, FTP, SMTP) contacted by the source IP.
- **Normal Range:** 1 (legitimate users hit one service)
- **Anomalous Range:** >1 (lateral exploration)
- **Rationale:** **Highest importance feature.** Any IP interacting with multiple honeypots is almost certainly performing reconnaissance.

### 12. `session_duration_estimate`
- **Source:** `packet_logs.timestamp`
- **Type:** Float (seconds)
- **Calculation:** Time delta between the first and last event from a source IP.
- **Normal Range:** <300s
- **Anomalous Range:** ≥300s
- **Rationale:** Very short sessions indicate scanning; very long sessions suggest persistent backdoor or tunneling.

### 13. `unique_destination_count`
- **Source:** `packet_logs.dst_ip`
- **Type:** Integer
- **Calculation:** Count of unique destination IPs contacted by the source IP.
- **Rationale:** High fan-out is a hallmark of network reconnaissance and horizontal scanning behavior.

### 14. `rolling_average_deviation`
- **Source:** `packet_logs` (1-hour window)
- **Type:** Float
- **Calculation:** Deviation of the current event rate from the 1-hour rolling average for that source IP.
- **Rationale:** Sudden surges detected via deviation indicate the start of an attack campaign.

### 15. `z_score_anomaly`
- **Source:** `packet_logs` (all features)
- **Type:** Float
- **Calculation:** Statistical Z-score of the packet length compared to the global mean and standard deviation.
- **Normal Range:** -2 to 2
- **Anomalous Range:** <-2 or >2
- **Rationale:** Aggregate statistical measure that captures extreme outliers across the feature distribution.

---

## Preprocessing Pipeline

| Step | Method | Details |
|---|---|---|
| 1. Missing Value Handling | Zero imputation | Missing values replaced with `0` |
| 2. Categorical Encoding | Label encoding | `protocol_encoding`, `destination_port_class` mapped to integers |
| 3. Boolean Conversion | Binary encoding | `time_of_day_deviation` converted to 0/1 |
| 4. Feature Scaling | `StandardScaler` | All features standardized to mean=0, variance=1 |
| 5. Scaler Persistence | Serialized | `models/scaler_v1.pkl` — must be loaded at inference time |

### Preprocessing Code Example
```python
from sklearn.preprocessing import StandardScaler
import joblib

# Load the fitted scaler
scaler = joblib.load("models/scaler_v1.pkl")

# Transform incoming feature vector
features_scaled = scaler.transform([raw_feature_vector])
```

---

## Feature Categories Summary

| Category | Features | Count | Total Importance |
|---|---|---|---|
| **Rate-based** | `source_ip_event_rate`, `burst_rate` | 2 | 24.3% |
| **Behavioral** | `honeypot_interaction_count`, `attack_type_frequency` | 2 | 18.3% |
| **Statistical** | `z_score_anomaly`, `rolling_average_deviation` | 2 | 13.7% |
| **Historical** | `malicious_flag_ratio` | 1 | 9.8% |
| **Heuristic** | `threat_score` | 1 | 9.1% |
| **Network** | `unique_destination_count`, `destination_port_class`, `protocol_encoding` | 3 | 11.1% |
| **Packet** | `packet_length`, `packet_size_variance` | 2 | 7.4% |
| **Temporal** | `session_duration_estimate`, `time_of_day_deviation` | 2 | 6.3% |
