# PHANTOMNET UNIFIED FEATURE SPECIFICATION
**Version:** 3.0.0 (Canonical Production Contract)  
**Status:** ACTIVE & ENFORCED  
**Implementation:** [`backend/ml/feature_extractor.py`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/feature_extractor.py)  
**Validation Suite:** [`tests/ml/test_feature_extractor_remediated.py`](file:///c:/Users/srira/Project/PhantomNet/tests/ml/test_feature_extractor_remediated.py)

---

## 1. Architectural Contract & Invariants

To eliminate feature misalignment, positional slicing hacks (`iloc[:, :12]`), and target leakage between offline research training and real-time production inference:

1. **Dimensional Invariance:** Production feature extraction produces strictly $D = 12$ continuous numeric features in an exact, invariant order.
2. **Explicit Name Alignment:** Models and transformers accept explicit named pandas DataFrames or typed NumPy vectors matching `FEATURE_NAMES`. Positional indexing without column name verification is strictly forbidden.
3. **Temporal Availability:** All 12 features are computed solely from packet header metadata, flow buffers, or streaming sliding-window telemetry available at line rate before threat scoring.
4. **Zero Leakage:** No post-event metrics (e.g., `threat_score`, `cluster_id`, `campaign_risk_index`, `playbook_id`) are permitted in the feature pipeline.

---

## 2. Canonical 12-Dimensional Feature Schema

| Index | Feature Name | Dtype | Unit | Allowed Range | Transformation | Ingestion Source | Inference Available? | State-Derived? | Leakage Status |
| :---: | :--- | :---: | :---: | :---: | :--- | :--- | :---: | :---: | :--- |
| **0** | `packet_size` | `float64` | Bytes | $[0, 65535]$ | Clamped to bounds | Packet header length | **YES** | No | Clean |
| **1** | `flow_duration` | `float64` | Seconds | $[0.0, 86400.0]$ | $\Delta t = t_{now} - t_{flow\_start}$ | Flow tracker table | **YES** | Yes (Window) | Clean |
| **2** | `packet_rate` | `float64` | Pkts/sec | $[0.0, 10^7]$ | $\frac{N_{packets}}{\max(\Delta t, 0.001)}$ | Streaming window buffer | **YES** | Yes (Window) | Clean |
| **3** | `byte_rate` | `float64` | Bytes/sec | $[0.0, 10^9]$ | $\frac{N_{bytes}}{\max(\Delta t, 0.001)}$ | Streaming window buffer | **YES** | Yes (Window) | Clean |
| **4** | `syn_ratio` | `float64` | Ratio | $[0.0, 1.0]$ | $\frac{N_{SYN}}{\max(N_{packets}, 1)}$ | TCP control flags | **YES** | Yes (Window) | Clean |
| **5** | `ack_ratio` | `float64` | Ratio | $[0.0, 1.0]$ | $\frac{N_{ACK}}{\max(N_{packets}, 1)}$ | TCP control flags | **YES** | Yes (Window) | Clean |
| **6** | `payload_entropy` | `float64` | Bits/byte| $[0.0, 8.0]$ | $-\sum p_i \log_2(p_i)$ | Raw packet payload | **YES** | No | Clean |
| **7** | `failed_logins` | `float64` | Count | $[0, 10^5]$ | Rolling event count | Auth log filter / DPI | **YES** | Yes (Window) | Clean |
| **8** | `port_diversity` | `float64` | Count | $[1, 65535]$ | Unique DST ports visited | Sliding window set | **YES** | Yes (Window) | Clean |
| **9** | `inter_arrival_mean` | `float64` | Seconds | $[0.0, 3600.0]$ | $\mathrm{Mean}(\Delta t_i)$ | Packet arrival timestamps | **YES** | Yes (Window) | Clean |
| **10** | `window_size_mean` | `float64` | Bytes | $[0, 65535]$ | $\mathrm{Mean}(W_i)$ | TCP window advertisement | **YES** | Yes (Window) | Clean |
| **11** | `ttl_mean` | `float64` | Hops | $[0, 255]$ | $\mathrm{Mean}(\mathrm{TTL}_i)$ | IPv4/IPv6 TTL / Hop limit | **YES** | Yes (Window) | Clean |

---

## 3. Runtime Verification & Defensive Guarantees

The production `FeatureExtractor` enforces:

```python
FEATURE_NAMES = [
    "packet_size",
    "flow_duration",
    "packet_rate",
    "byte_rate",
    "syn_ratio",
    "ack_ratio",
    "payload_entropy",
    "failed_logins",
    "port_diversity",
    "inter_arrival_mean",
    "window_size_mean",
    "ttl_mean",
]
```

### 3.1 Non-Finite and Missing Value Policy
1. **Missing Keys:** Extractor defaults to defined baseline network priors (e.g., `packet_size = 64.0`, `ttl_mean = 64.0`, `failed_logins = 0.0`).
2. **NaN / Inf Clamping:** All numerical outputs are passed through `np.nan_to_num(val, nan=0.0, posinf=max_val, neginf=min_val)` before matrix construction.
3. **Shape Assertions:** Every output matrix is verified against shape $(N, 12)$. Any call passing a mismatched dimensionality fails fast with a typed `ValueError`.

### 3.2 Thread-Safety & Window Isolation
- IP-keyed sliding windows are managed in a bounded LRU eviction cache with a thread `RLock` to prevent data race conditions between concurrent ingestion workers.
- Window states are partitioned strictly by `src_ip`. Activity from Source IP $A$ cannot contaminate the flow buffer or metrics of Source IP $B$.
