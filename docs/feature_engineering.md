# Feature Engineering Documentation

## Overview
The PhantomNet Isolation Forest model uses **15 extracted features** to detect network anomalies. These features are derived from raw packet logs and aggregated stats.

## Feature List

| Feature Name | Description | Rationale |
|--------------|-------------|-----------|
| `packet_length` | Size of the packet in bytes. | Unusually large or small packets can indicate buffer overflow attempts or command-and-control beacons. |
| `protocol_encoding` | Numerical encoding of the protocol (TCP=6, UDP=17, ICMP=1, etc.). | Certain protocols are more commonly associated with specific attack vectors. |
| `source_ip_event_rate` | Number of events from this Source IP in the last minute. | High rates suggest DoS/DDoS attacks or brute-force attempts. |
| `destination_port_class` | Classification of port (0=Well-Known, 1=Registered, 2=Dynamic). | Attacks often target specific well-known ports or use random dynamic ports. |
| `threat_score` | Heuristic score assigned by the rule-based engine (0-100). | Provides a baseline "suspicion level" from known signatures. |
| `malicious_flag_ratio` | Ratio of packets from this IP flagged as malicious in history. | History of bad behavior increases likelihood of future attacks. |
| `attack_type_frequency` | Frequency of this specific attack type in recent logs. | sudden spikes in a specific attack type indicate a coordinated campaign. |
| `time_of_day_deviation` | Deviation from average traffic volume for this hour of day. | Attacks often occur at off-peak hours to avoid detection. |
| `burst_rate` | Max number of packets received in any 1-second window within the flow. | Indicates bursty traffic characteristic of flooding attacks. |
| `packet_size_variance` | Variance in packet sizes for the flow/session. | automated tools often use fixed packet sizes, unlike human traffic. |
| `honeypot_interaction_count` | Number of times this IP has interacted with honeypots. | Any interaction with a honeypot is highly suspicious. |
| `session_duration_estimate` | Estimated duration of the connection flow. | Very short (scan) or very long (tunneling) sessions are anomalies. |
| `unique_destination_count` | Number of unique destination IPs this source has contacted. | High fan-out indicates network scanning/reconnaissance. |
| `rolling_average_deviation` | Deviation of current event rate from 1-hour rolling average. | Detects sudden surges in traffic volume. |
| `z_score_anomaly` | Statistical Z-score of the packet length vs global mean. | Measures how extreme the packet size is compared to normal distribution. |

## Preprocessing
- **Imputation:** Missing values are replaced with `0`.
- **Scaling:** All features are standardized (mean=0, variance=1) using `StandardScaler`.
