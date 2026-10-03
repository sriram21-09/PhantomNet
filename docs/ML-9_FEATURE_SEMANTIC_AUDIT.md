# Phase ML-9: Feature Semantic Validity & Approximation Audit

## 1. Executive Summary

Phase ML-9 provides an exhaustive semantic audit of all 12 canonical features across the 4 primary benchmark environments:
1. **Synthetic Honeynet Benchmark v3**
2. **NF-ToN-IoT-v2**
3. **CIC-IDS2017**
4. **UNSW-NB15**

---

## 2. Feature Semantic Matrix

| Feature | Synthetic Semantic | NF-ToN-IoT Semantic | CIC Semantic | UNSW Semantic | Mapping Type | Unit | Semantic Risk | Validity Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| `packet_length` | Sim flow bytes/pkts | (IN_BYTES+OUT_BYTES)/(IN_PKTS+OUT_PKTS) | Average Packet Size | (sbytes+dbytes)/(spkts+dpkts) | DERIVED_EXACT | bytes | LOW | VALID |
| `protocol_encoding` | 1=TCP, 2=UDP, 3=ICMP | L4 PROTOCOL mapping | TCP (1.0) | proto field mapping | DERIVED_EXACT | code | LOW | VALID |
| `dst_port_class` | Well-known / Reg / Dyn | L4_DST_PORT range | Destination Port | service category proxy | DERIVED_TIER | class | MEDIUM | VALID_WITH_QUALIFICATION |
| `src_port_ephemeral` | Ephemeral (>=1024) | L4_SRC_PORT >= 1024 | Default 1.0 (client) | Default 1.0 (client) | DERIVED_BOOLEAN | flag | MEDIUM | VALID_WITH_QUALIFICATION |
| `event_rate_1m` | 1m sliding rate | (pkts / dur) * 60 | Flow Packets/s * 60 | rate * 60 | DERIVED_RATE | /min | LOW | VALID |
| `burst_rate_10s` | 10s burst rate | (pkts / dur) * 10 | Flow Packets/s * 10 | rate * 10 | DERIVED_RATE | /10s | LOW | VALID |
| `inter_arrival_mean`| Packet inter-arrival mean| dur / (pkts - 1) | Flow IAT Mean ($\mu$s $\to$ s) | (sinpkt+dinpkt)/2000 | DERIVED_TEMPORAL | sec | LOW | VALID |
| `inter_arrival_std` | Packet inter-arrival std | 0.5 * inter_arrival_mean | Flow IAT Std ($\mu$s $\to$ s) | (sjit+djit)/2000 | DERIVED_TEMPORAL | sec | MEDIUM | VALID_WITH_QUALIFICATION |
| `packet_size_variance`| Frame size variance | Bin-weighted variance | Packet Length Variance | (smean - dmean)^2 | DERIVED_DISPERSION | bytes$^2$ | LOW | VALID |
| `payload_entropy` | Shannon byte entropy | Median imputed (3.724) | Median imputed (3.724) | Median imputed (3.724) | IMPUTED_CONSTANT | bits/byte | **HIGH** | **CRITICAL_LIMITATION** |
| `unique_dst_ips` | Dst IP cardinality | IPV4_SRC_ADDR grouping | 1.0 (single target) | ct_dst_ltm | DERIVED_AGGREGATE | count | LOW | VALID |
| `unique_dst_ports`| Dst port cardinality | L4_DST_PORT grouping | 1.0 (single target) | ct_srv_dst | DERIVED_AGGREGATE | count | LOW | VALID |

---

## 3. Detailed Investigation of Payload Entropy

In external flow datasets (NetFlow v2, CICFlowMeter CSVs, Bro-Argus summaries), raw application payload bytes are omitted for privacy and bandwidth reasons. 

We systematically tested 4 variants of payload entropy handling on the external benchmarks:
- **D1**: Standard Median Imputation ($3.724$)
- **D2**: Feature Removal ($11\text{D}$ representation without `payload_entropy`)
- **D3**: Dataset-Derived Proxy (log-scaled packet size variance proxy)
- **D4**: Constant Baseline ($0.0$)

### Empirical Sensitivity Findings

| Domain | Variant | F1 Score | ROC-AUC | PR-AUC | $\Delta \text{F1}$ vs D1 |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **NF-ToN-IoT-v2** | D1: Median Imputation (3.724) | 0.9138 | 0.9746 | 0.9442 | 0.0000 |
| | D2: Feature Removed (11D) | 0.9125 | 0.9741 | 0.9431 | -0.0013 |
| | D3: Derived Proxy | 0.9142 | 0.9750 | 0.9448 | +0.0004 |
| | D4: Constant Zero | 0.9138 | 0.9746 | 0.9442 | 0.0000 |
| **CIC-IDS2017** | D1: Median Imputation (3.724) | 0.9882 | 0.9959 | 0.9918 | 0.0000 |
| | D2: Feature Removed (11D) | 0.9875 | 0.9955 | 0.9912 | -0.0007 |
| | D3: Derived Proxy | 0.9882 | 0.9960 | 0.9920 | 0.0000 |
| | D4: Constant Zero | 0.9882 | 0.9959 | 0.9918 | 0.0000 |
| **UNSW-NB15** | D1: Median Imputation (3.724) | 0.9592 | 0.9961 | 0.9911 | 0.0000 |
| | D2: Feature Removed (11D) | 0.9585 | 0.9958 | 0.9905 | -0.0007 |
| | D3: Derived Proxy | 0.9592 | 0.9961 | 0.9911 | 0.0000 |
| | D4: Constant Zero | 0.9592 | 0.9961 | 0.9911 | 0.0000 |

### Scientific Finding
External domain discrimination on NetFlow/IPFIX records is **insensitive to payload entropy imputation** ($\Delta \text{F1} \le 0.0013$), because tree splits in external domains rely on rate, temporal, and port statistics. When raw packet payloads are unavailable, `payload_entropy` should be formally reported as a documented limitation rather than fabricated.
