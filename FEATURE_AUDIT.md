# PhantomNet Feature Engineering & Preprocessing Deep Audit

**Document:** Feature Pipeline Forensic Audit (`FEATURE_AUDIT.md`)  
**Auditor:** Lead ML & Reproducibility Auditor  
**Date:** 2026-10-01  
**Project:** PhantomNet  
**Status:** COMPLETE — REMEDIATION SPECIFIED  

---

## 1. Feature Extractor Fragmentation & Architectural Drift

A critical finding of this audit is severe architectural fragmentation. Instead of a single, unified feature extraction pipeline, the codebase contains **six competing, incompatible feature implementations**:

| Module Path | Feature Count | Target Domain | Normalization / Scaling | Used by Runtime? |
|---|---|---|---|---|
| `backend/ml/feature_extractor.py` | 15 | Network Socket Flow Telemetry | None (Raw numerical features) | **YES** (`threat_scoring_service.py`) |
| `backend/ml/feature_engineering_v2.py` | 12 | Host / Payload Behavioral Telemetry | None (Raw counts/entropies) | **NO** (Only dataset generation & `reproduce_paper.py`) |
| `backend/ml/feature_engineering_complete.py` | 32 | Composite (15 Base + 12 V2 + 5 Extensions) | None | **NO** (Experimental prototype) |
| `backend/ml/preprocessor.py` | 11 | Mixed Flow & Payload | Split `StandardScaler` + `MinMaxScaler` | **NO** (Unwired legacy preprocessor) |
| `backend/services/feature_extractor.py` | 6 | Simple Netflow (Duration, Subnet, Proto) | MinMax via static dict thresholds | **NO** (`ai_engine/train_final.py` only) |
| `backend/ml/train_model.py` | 3 | Minimal Ports & Protocol (`src_port`, `dst_port`, `proto`) | None | **NO** (`isolation_forest_v1.pkl` only) |

### The "23-Dimensional" Discrepancy Resolved
- The repository documentation (`README.md`, `report_data/06_ml.md`, architectural diagrams) repeatedly claims a **"23D Feature Vector Ensemble"**.
- In reality, no 23-dimensional feature extractor exists in executable code.
- Origin: An early architectural proposal planned to concatenate the 15 network flow features with 8 behavioral indicators ($15 + 8 = 23$). This plan was abandoned when development froze the 15-dimensional `FeatureExtractor` as active. The 23D claim is documentation debt and must be corrected to the true audited dimensionality.

---

## 2. In-Depth Audit of the Active 15D Feature Extractor

**File:** `backend/ml/feature_extractor.py` (`FeatureExtractor`)

| # | Feature Name | Mathematical Definition / Logic | Leakage Assessment | Numerical Stability & Edge Cases |
|---|---|---|---|---|
| 1 | `packet_length` | $L = \text{int}(\text{event.get}(\text{"length"}, 0))$ | Clean | Bound to $[0, 65535]$. Stable. |
| 2 | `protocol_encoding` | $\text{TCP} \to 1, \text{UDP} \to 2, \text{ICMP} \to 3, \text{Other} \to 0$ | Clean | Discrete integer mapping. |
| 3 | `source_ip_event_rate` | $\frac{\sum_{e \in \text{events}(IP, \Delta t)} 1}{\Delta t}$ | Clean | Uses sliding window ($\Delta t = 60\text{s}$). |
| 4 | `destination_port_class` | $1 \text{ if } p \le 1023 \text{ else } (2 \text{ if } p \le 49151 \text{ else } 3)$ | Clean | Well-known vs Registered vs Ephemeral. |
| 5 | **`threat_score`** | $\text{float}(\text{event.get}(\text{"threat_score"}, 0.0))$ | **CRITICAL CIRCULAR LEAKAGE** | **FATAL:** Ingests the model's own target output as an input feature. In synthetic datasets, benign is $0.0$ and attack is $0.6$ or $>0.4$. |
| 6 | **`malicious_flag_ratio`** | $\frac{\sum \text{flags}_{\text{malicious}}(IP)}{\|\text{events}(IP)\|}$ | **CRITICAL DIRECT LABEL LEAKAGE** | **FATAL:** Reads ground truth `is_malicious` flag directly from event input. Perfectly separates classes in `labeled_events_15d_unified.csv`. |
| 7 | **`attack_type_frequency`** | $\text{count}(\text{event.get}(\text{"attack_type"}))$ | **INDIRECT LABEL LEAKAGE** | Leaks categorical attack labels assigned during data synthesis. |
| 8 | `time_of_day_deviation` | $1 \text{ if } \text{hour} \in [0, 5] \text{ else } 0$ | Questionable | Assumes attacker only operates at night; synthetic data toggles this rigidly. |
| 9 | `burst_rate` | $\max_{\tau \le 10\text{s}} \text{events}(IP, \tau)$ | Clean | Sub-window peak event density. |
| 10 | `packet_size_variance` | $\frac{1}{N-1} \sum (L_i - \bar{L})^2$ | Clean | Falls back to $0.0$ if $N < 2$. Stable. |
| 11 | `honeypot_interaction_count` | $\|\text{unique}(\text{honeypot\_ids})\|$ | Clean | Cardinality of honeypot services touched. |
| 12 | `session_duration_estimate` | $T_{\text{last}} - T_{\text{first}}$ (seconds) | Clean | In synthetic data, artificially inflated to $>600,000$ for attacks. |
| 13 | `unique_destination_count` | $\|\text{unique}(\text{dst\_ips})\|$ | Clean | Cardinality of destination IPs targeted. |
| 14 | `rolling_average_deviation` | $\|L_{\text{current}} - \bar{L}_{IP}\|$ | Clean | Deviation from moving average. |
| 15 | `z_score_anomaly` | $\frac{L - \mu}{\sigma + 10^{-6}}$ | Clean | Z-score normalization of packet size. |

---

## 3. Runtime Feature Alignment Breakdown

**File:** `backend/ml/threat_scoring_service.py:L155-168`

When `score_threat(input_data)` is called in production:
```python
# 1. FeatureExtractor produces 15 network flow features
features_dict = _FEATURE_EXTRACTOR.extract_features(event)
feature_vector = pd.DataFrame([features_dict], columns=FeatureExtractor.FEATURE_NAMES)

# 2. Model in registry (AttackClassifier_Enhanced_v1.0.0.pkl) expects 12 features
if hasattr(model, "n_features_in_") and model.n_features_in_ == 12:
    X_input = feature_vector.iloc[:, :12].values # SLICES FIRST 12 COLUMNS!
```

### The Semantic Catastrophe
The model was trained on `FeatureExtractorV2` (12 behavioral dimensions). The runtime feeds the first 12 columns of `FeatureExtractor` (15 network dimensions).

| Slot | Model Expected Feature | Actual Runtime Input Supplied | Consequence |
|---|---|---|---|
| 0 | `command_count` | `packet_length` (e.g., 1500) | Model thinks attacker ran 1,500 shell commands |
| 1 | `avg_command_length` | `protocol_encoding` (1 or 2) | Model thinks average command length was 1 byte |
| 2 | `shell_escape_count` | `source_ip_event_rate` (e.g., 25) | Model thinks packet had 25 bash `;` escapes |
| 3 | `directory_traversal_count` | `destination_port_class` (1, 2, or 3) | Model thinks packet had 3 `../` path traversals |
| 4 | `failed_login_count` | `threat_score` (0.0 to 1.0) | Floating point injected into integer failure count |
| 5 | `payload_entropy` | `malicious_flag_ratio` (0.0 or 1.0) | Ratio injected into entropy slot (entropy typically 2.5–4.5) |
| 6 | `interaction_interval_var` | `attack_type_frequency` (int count) | Event count treated as temporal variance |
| 7 | `persistence_score` | `time_of_day_deviation` (0 or 1) | Binary hour flag treated as hourly persistence |
| 8 | `ua_diversity` | `burst_rate` (peak 10s events) | Burst count treated as User-Agent string diversity |
| 9 | `lateral_movement_index` | `packet_size_variance` (float variance) | Packet variance (e.g. 50,000) treated as ratio in $[0, 1]$ |
| 10 | `sensitive_file_count` | `honeypot_interaction_count` (int) | Honeypot ID count treated as `/etc/shadow` touches |
| 11 | `payload_to_cmd_ratio` | `session_duration_estimate` (seconds) | Session duration (seconds) treated as ratio |

**Verdict:** The deployed model at runtime was operating on completely scrambled, nonsensical features. It produced random or constant predictions regardless of true traffic nature.

---

## 4. Preprocessing & Normalization Deficiencies

1. **Scaler Missing in Production:** `campaign_clustering.py` calls `fit_predict` directly on raw data with no `StandardScaler`. Destination ports ($22 \to 2222 \to 8080$) dominate Euclidean distance, rendering intervals and entropy irrelevant and producing 100% noise.
2. **Scaler Mismatch in Scoring:** `threat_scoring_service.py` runs inference directly on unscaled feature vectors, bypassing `feature_scaler_v2.pkl` or `scaler_unified.pkl`.
3. **Improper Fit vs. Transform:** In `backend/ml/preprocessing.py:L44`, `scaler.fit_transform(X)` is called inside `process_and_label()` during training without persisting validation split boundaries, risking data leakage across cross-validation folds.

---

## 5. Remediation Architecture for Feature Engineering

To achieve strict scientific rigor and runtime stability, the feature pipeline must be refactored into a single, unified module:

1. **Clean Feature Definition (12 Dimensions, Zero Leakage):**
   - Pure network & transport observables:
     1. `packet_length` (bytes)
     2. `protocol_encoding` (TCP/UDP/ICMP)
     3. `src_port_entropy` (ephemeral port randomization)
     4. `dst_port_class` (Well-known / Registered / Ephemeral)
     5. `event_rate_1m` (Events/min from source IP)
     6. `burst_rate_10s` (Peak 10-second burst rate)
     7. `inter_arrival_time_mean` (Mean delta seconds between packets)
     8. `inter_arrival_time_std` (Variance in packet timing; detects automation)
     9. `packet_size_variance` (Variance of length over IP window)
     10. `payload_entropy` (Shannon entropy of raw data payload)
     11. `connection_count_unique_dst` (Distinct destination IPs probed)
     12. `service_cardinality` (Distinct target ports probed)
2. **Explicit Separation from Threat Targets:**
   - Ban `threat_score`, `is_malicious`, `malicious_flag_ratio`, and `attack_type` from the feature vector.
3. **Mandatory Pipeline Coupling:**
   - The trained model artifact must bundle its fitted `StandardScaler` inside a scikit-learn `Pipeline` (`Pipeline([('scaler', StandardScaler()), ('classifier', RandomForestClassifier())])`).
   - This guarantees that unscaled features can never be passed to the model at runtime, and feature names/order are enforced automatically.
