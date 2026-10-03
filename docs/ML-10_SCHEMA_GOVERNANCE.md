# ML-10: 12D Schema Governance & Feature-Quality Gating

---

## 1. Executive Summary

Phase ML-10 implements a deterministic, fail-closed feature schema and quality gating engine ([schema_gate.py](file:///c:/Users/srira/Project/PhantomNet/backend/ml/ml10/schema_gate.py)) enforcing strict conformance to the 12D-v1 canonical feature contract prior to model inference.

---

## 2. 12D-v1 Canonical Feature Contract Specification

| Dimension | Feature Name | Description | Bound Min | Bound Max | Negative Allowed |
| :---: | :--- | :--- | :---: | :---: | :---: |
| 1 | `packet_length` | Total IP packet length in bytes | 0.0 | 65,535.0 | False |
| 2 | `protocol_encoding` | IANA protocol number (e.g. 6=TCP, 17=UDP) | 0.0 | 255.0 | False |
| 3 | `dst_port_class` | Categorical port classification | 0.0 | 10.0 | False |
| 4 | `src_port_ephemeral` | Binary indicator for ephemeral source port | 0.0 | 1.0 | False |
| 5 | `event_rate_1m` | Aggregate network flow rate per minute | 0.0 | 1e9 | False |
| 6 | `burst_rate_10s` | Short-term burst event rate (10-second window) | 0.0 | 1e9 | False |
| 7 | `inter_arrival_mean` | Mean inter-arrival duration between packets | 0.0 | 1e7 | False |
| 8 | `inter_arrival_std` | Standard deviation of packet inter-arrival times | 0.0 | 1e7 | False |
| 9 | `packet_size_variance` | Empirical variance of packet payload sizes | 0.0 | 1e12 | False |
| 10 | `payload_entropy` | Byte-level Shannon entropy | 0.0 | 8.0 | False |
| 11 | `unique_dst_ips` | Count of unique destination IP addresses | 0.0 | 1e9 | False |
| 12 | `unique_dst_ports` | Count of unique destination ports targeted | 0.0 | 65,535.0 | False |

---

## 3. Severity Classification & Enforcement Policy

1. **`VALID`**: All 12 canonical features present in exact sequence, finite numerical values within physical bounds. Admissible for inference.
2. **`WARNING`**: Non-critical anomalies (e.g., zero-filled telemetry or minor benign outliers). Permitted with audit logging.
3. **`SEVERE`**: Physical range violations, extreme statistical anomalies.
4. **`REJECT`**: Dimensionality mismatch (11D, 13D, 32D), missing keys, NaN, $\pm\infty$, or impossible negative durations/byte counts. **Fails closed to quarantine.**

---

## 4. Empirical Validation Matrix

All 11 test cases in the validation matrix achieved 100% adherence:
- `valid_canonical_record` -> `VALID` (Admissible)
- `nan_corruption` -> `REJECT` (Quarantined)
- `positive_inf_corruption` -> `REJECT` (Quarantined)
- `negative_duration` -> `REJECT` (Quarantined)
- `negative_bytes` -> `REJECT` (Quarantined)
- `missing_dimension_11d` -> `REJECT` (Quarantined)
- `extra_dimension_13d` -> `REJECT` (Quarantined)
- `zero_filled_telemetry` -> `WARNING` (Admissible with log)
- `valid_external_benchmark_records` -> `VALID` (Admissible)
