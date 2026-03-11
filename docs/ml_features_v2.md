# Machine Learning Feature Documentation v2

This document describes the 30+ features used by the `AttackClassifierV3`.

## Base Features (1-15)
*Established in previous versions.*
1. `packet_length`
2. `protocol_encoding`
... (Refer to `feature_extractor.py`)

## Behavioral Features (16-30+)
*Implemented in Week 11 Day 1.*

| Feature | Description |
|---------|-------------|
| `command_count` | Number of commands detected in raw data. |
| `avg_command_length` | Average length of commands. |
| `shell_escape_count` | Occurrences of shell escape characters. |
| `directory_traversal_count` | Occurrences of `../` or `..\\`. |
| `failed_login_count` | Number of failed login attempts. |
| `payload_entropy` | Shannon entropy of the raw payload data. |
| `interaction_interval_var` | Variance of time intervals between interactions. |
| `persistence_score` | Count of sessions over distinct hour blocks. |
| `ua_diversity` | Number of unique User-Agents. |
| `lateral_movement_index` | Ratio of unique destination IPs to total events. |
| `sensitive_file_count` | Access attempts to sensitive files. |
| `payload_to_cmd_ratio` | Ratio of total payload size to the number of commands. |

## Normalization
All features are normalized using `StandardScaler` (saved in `models/feature_scaler_v2.pkl`) to ensure model stability and performance.
