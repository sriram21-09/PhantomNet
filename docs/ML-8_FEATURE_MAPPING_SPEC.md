# PhantomNet Phase ML-8: Canonical Feature Mapping Specification

## 1. Overview and Mapping Principles

PhantomNet's canonical 12-dimensional feature schema (`12D-v1`) was designed to capture transport-layer packet geometry, timing dynamics, host diversity, and payload complexity without deep packet inspection. In Phase ML-8, external datasets were mapped to this canonical contract under strict audit guidelines:

- **No Silent Zero-Filling**: Unavailable features must be documented explicitly with quantified information loss.
- **Classification Categories**: Every feature mapping is formally categorized as:
  - `DIRECT`: Exact 1-to-1 match with external source telemetry.
  - `DERIVED`: Mathematically constructed from external flow telemetry without target dependence.
  - `APPROXIMATED`: Estimated from available metadata or nominal baseline due to telemetry omission in the source format.
  - `UNAVAILABLE`: Missing entirely and cannot be approximated without compromising scientific validity.

---

## 2. Feature Mapping Audit Table

| Canonical Feature (`12D-v1`) | NF-ToN-IoT-v2 Mapping | CIC-IDS2017 Mapping | UNSW-NB15 Mapping | Mapping Class | Information Loss / Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`packet_length`** | `(IN_BYTES + OUT_BYTES) / max(1, IN_PKTS + OUT_PKTS)` | `Average Packet Size` | `(sbytes + dbytes) / max(1, spkts + dpkts)` | DERIVED / DIRECT | Minimal; exact mean packet length. |
| **`protocol_encoding`** | `PROTOCOL` (TCP=1, UDP=2, ICMP=3) | Assigned `1.0` (TCP for DDoS/PortScan) | `proto` string mapped to numeric | DERIVED / APPROX | Minimal; protocols preserved. |
| **`dst_port_class`** | `L4_DST_PORT` classified (<=1023: 1, <=49151: 2, >49151: 3) | `Destination Port` classified | `service` string classified | DERIVED / APPROX | Minimal; well-known port boundaries preserved. |
| **`src_port_ephemeral`** | `1.0` if `L4_SRC_PORT` >= 1024 else `0.0` | Assigned `1.0` (client ephemeral) | Assigned `1.0` (client ephemeral) | DERIVED / APPROX | Low; standard client socket behavior. |
| **`event_rate_1m`** | `tot_pkts / duration_sec * 60` | `Flow Packets/s * 60` | `rate * 60` | DERIVED | Moderate; derived from flow packet rate. |
| **`burst_rate_10s`** | `tot_pkts / duration_sec * 10` | `Flow Packets/s * 10` | `rate * 10` | DERIVED | Moderate; sub-flow burst proxy. |
| **`inter_arrival_mean`** | `duration_sec / max(1, tot_pkts - 1)` | `Flow IAT Mean / 1e6` (sec) | `(sinpkt + dinpkt) / 2000` (sec) | DERIVED | Low; inter-packet timing preserved. |
| **`inter_arrival_std`** | `inter_arrival_mean * 0.5` | `Flow IAT Std / 1e6` (sec) | `(sjit + djit) / 2000` (sec) | DERIVED / APPROX | Moderate; jitter proxy in NetFlow. |
| **`packet_size_variance`** | Derived from binned packet size histograms | `Packet Length Variance` | `(smean - dmean)^2` | DERIVED / DIRECT | Low; variance accurately captured. |
| **`payload_entropy`** | Imputed with nominal median (`3.724`) | Imputed with nominal median (`3.724`) | Imputed with nominal median (`3.724`) | **APPROXIMATED** | **CRITICAL**: NetFlow, CICFlowMeter CSVs, and Argus flow records strip raw packet payload for privacy reasons; payload entropy cannot be computed directly. |
| **`unique_dst_ips`** | `groupby(IPV4_SRC_ADDR)['IPV4_DST_ADDR'].nunique()` | Assigned `1.0` (IPs stripped in ISCX CSV) | `ct_dst_ltm` | DERIVED / APPROX | Moderate; isolated CSV rows lack rolling cross-host context. |
| **`unique_dst_ports`** | `groupby(IPV4_SRC_ADDR)['L4_DST_PORT'].nunique()` | Assigned `1.0` | `ct_srv_dst` | DERIVED / APPROX | Moderate; isolated CSV rows lack rolling cross-host context. |

---

## 3. Critical Mapping Findings & Telemetry Gaps

1. **Payload Entropy Omission**: The single most critical telemetry gap across public flow datasets is the absence of raw packet payloads. Because NetFlow v2 and CICFlowMeter omit payload bytes to preserve confidentiality and reduce storage overhead, `payload_entropy` had to be approximated using the empirical prior median ($3.724$) established in Phase ML-7 missingness analyses. This introduces an unavoidable information loss regarding application-layer encryption and packing.
2. **Rolling Multi-Host State**: In production PhantomNet engines, `unique_dst_ips` and `unique_dst_ports` are calculated in real time across a 60-second sliding window. In pre-extracted tabular datasets where records represent isolated flows, multi-host state can only be approximated via grouping or localized connection counters.
