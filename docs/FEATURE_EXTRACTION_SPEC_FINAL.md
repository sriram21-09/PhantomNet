# PhantomNet — Feature Extraction Specification (Final)

## Purpose
This document defines the complete and frozen set of ML features
used for threat analysis and behavioral modeling.

All features are derived from real ingestion data and do not require
schema changes to existing tables.

Primary source of truth:
- packet_logs
Secondary enrichment:
- ssh_logs, http_logs, ftp_logs, asyncssh_logs

Total number of features: 15

### 1. Packet Length
- Source: packet_logs.length
- Data Type: Integer
- Calculation: Raw packet size in bytes
- Normal Range: 40–1500
- Anomalous Range: <40 or >1500
- Rationale: Detect malformed packets and flood anomalies

### 2. Protocol Encoding
- Source: packet_logs.protocol
- Data Type: Categorical (encoded)
- Calculation: Map protocol to numeric label
- Normal Range: Known protocols

### 3. Source IP Event Rate
- Source: packet_logs.src_ip
- Data Type: Float
- Calculation: Events per source IP per minute
- Normal Range: <20
- Anomalous Range: >=20
- Rationale: Detect scanning and brute-force behavior
- 
### 4. Destination Port Class
- Source: packet_logs.dst_port
- Data Type: Categorical
- Calculation: Well-known / Registered / Ephemeral
- Normal Range: Expected per honeypot
- Anomalous Range: Unexpected port access
- Rationale: Detect lateral probing

### 5. Threat Score
- Source: packet_logs.threat_score
- Data Type: Float
- Calculation: Existing scoring logic
- Normal Range: <50
- Anomalous Range: >=50
- Rationale: Baseline threat signal
- Anomalous Range: Unknown or rare protocols
- Rationale: Identify protocol misuse or evasion

### 6. Malicious Flag Ratio
- Source: packet_logs.is_malicious
- Data Type: Float
- Calculation: Ratio of malicious events per IP
- Normal Range: <0.3
- Anomalous Range: >=0.3
- Rationale: Persistent attacker identification

### 7. Attack Type Frequency
- Source: packet_logs.attack_type
- Data Type: Integer
- Calculation: Count per attack type per IP
- Normal Range: Low variance
- Anomalous Range: Repetitive single type
- Rationale: Tool-driven attack detection

### 8. Time of Day Deviation
- Source: packet_logs.timestamp
- Data Type: Boolean
- Calculation: Activity outside normal traffic hours
- Normal Range: False
- Anomalous Range: True
- Rationale: Detect off-hour automated attacks

### 9. Burst Rate
- Source: packet_logs.timestamp
- Data Type: Float
- Calculation: Max events per IP in 10-second window
- Normal Range: <10
- Anomalous Range: >=10
- Rationale: Flood and spray attacks

### 10. Packet Size Variance
- Source: packet_logs.length
- Data Type: Float
- Calculation: Variance of packet size per IP
- Normal Range: Low variance
- Anomalous Range: High variance
- Rationale: Payload manipulation detection

### 11. Honeypot Interaction Count
- Source: packet_logs.honeypot_type
- Data Type: Integer
- Calculation: Number of honeypots touched by IP
- Normal Range: 1
- Anomalous Range: >1
- Rationale: Lateral exploration behavior

### 12. Session Duration Estimate
- Source: packet_logs.timestamp
- Data Type: Float
- Calculation: Time between first and last event per IP
- Normal Range: <300s
- Anomalous Range: >=300s
- Rationale: Persistent intrusion detection

### 13. Unique Destination Count
- Source: packet_logs.dst_ip
- Data Type: Integer
- Calculation: Unique destinations per source IP
- Normal Range: Low
- Anomalous Range: High
- Rationale: Horizontal scanning detection

### 14. Rolling Average Deviation
- Source: packet_logs
- Data Type: Float
- Calculation: Deviation from rolling mean (windowed)
- Normal Range: Near zero
- Anomalous Range: Large deviation
- Rationale: Behavioral drift detection

### 15. Z-Score Anomaly
- Source: packet_logs
- Data Type: Float
- Calculation: Statistical z-score across features
- Normal Range: -2 to 2
- Anomalous Range: <-2 or >2
- Rationale: Aggregate anomaly indicator
