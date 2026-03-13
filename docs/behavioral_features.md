# Behavioral Features for Enhanced Detection

To improve the accuracy of our attack classifier, we are adding the following 10+ behavioral features. These features focus on attacker behavior within honeypots and network patterns.

| Feature Name | Description | Rationale |
|--------------|-------------|-----------|
| `command_count` | Number of commands detected in raw data. | High command counts indicate active exploitation. |
| `avg_command_length` | Average length of commands. | Automated scripts often use long, complex one-liners. |
| `shell_escape_count` | Occurrences of shell escape characters (`;`, `&&`, `|`, etc.). | Common in command injection and shell escape attempts. |
| `directory_traversal_count` | Occurrences of `../` or `..\\`. | Indicates path traversal and file discovery attempts. |
| `failed_login_count` | Number of failed login attempts from the same source. | Key indicator of brute force attacks. |
| `payload_entropy` | Shannon entropy of the raw payload data. | High entropy can indicate encrypted payloads or packed malware. |
| `interaction_interval_var` | Variance of time intervals between interactions. | Human behavior is irregular; automated tools are often periodic. |
| `persistence_score` | Count of sessions over distinct hour blocks. | Measures if the attacker returns over a long period. |
| `ua_diversity` | Number of unique User-Agents used by the source IP. | Botnets often rotate User-Agents to avoid detection. |
| `lateral_movement_index` | Ratio of unique destination IPs to total events. | High ratio indicates scanning or lateral movement behavior. |
| `sensitive_file_count` | Access attempts to sensitive files (e.g., `/etc/passwd`). | Clear indicator of malicious intent. |
| `payload_to_cmd_ratio` | Ratio of total payload size to the number of commands. | Distinguishes between interactive sessions and automated bulk uploads. |

## Implementation Strategy
- These features will be implemented in `backend/ml/feature_engineering_v2.py`.
- The `FeatureExtractorV2` will extend the base functionality to include these behavioral metrics.
- Features will be normalized using a specialized scaler to ensure model stability.
