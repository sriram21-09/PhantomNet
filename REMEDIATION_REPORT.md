# PhantomNet Scientific Remediation & Architecture Specification

**Document:** Remediation Design & Architecture Specification (`REMEDIATION_REPORT.md`)  
**Auditor:** Lead ML & Reproducibility Auditor  
**Date:** 2026-10-01  
**Project:** PhantomNet Threat Intelligence & Deception Framework  
**Status:** ARCHITECTURAL SPECIFICATION APPROVED — READY FOR EXECUTION  

---

## 1. Executive Summary of Remediation Strategy

The forensic audit revealed that the PhantomNet research artifacts suffered from:
1. Trivial class separability and circular/direct label leakage in datasets.
2. Scrambled feature slicing at runtime (`iloc[:, :12]`).
3. Complete baseline DBSCAN collapse (0 clusters, 100% noise) and poor standardized clustering (71% noise, false merges).
4. Fabricated statistical tests (hardcoded $2 \times 2$ Fisher's contingency matrix).
5. Broken serialized model checkpoints and runtime crash bugs (`TypeError` in SHAP explainer, missing `import os`).

This report specifies the mathematical, architectural, and operational engineering specifications to **completely remediate every component**. The remediation guarantees scientific validity, reproducible empirical proof, and autonomous end-to-end functionality.

---

## 2. Remediated 12-Dimensional Feature Space Contract

To eliminate all target/label leakage while preserving the ability to detect diverse threats across multiple protocols, the feature extraction pipeline is unified into a clean 12-dimensional vector:

$$\mathbf{x} = [x_1, x_2, \dots, x_{12}]^T \in \mathbb{R}^{12}$$

| Index | Feature Name | Description & Mathematical Formula | Domain Observables |
|---|---|---|---|
| 0 | `packet_length` | Raw packet frame length in bytes ($L \in [0, 65535]$) | IP frame header |
| 1 | `protocol_encoding` | One-hot / integer protocol encoding: $\text{TCP} \to 1, \text{UDP} \to 2, \text{ICMP} \to 3$ | IP protocol field |
| 2 | `dst_port_class` | Well-known ($1 \le p \le 1023 \to 1$), Registered ($1024 \le p \le 49151 \to 2$), Ephemeral ($p \ge 49152 \to 3$) | TCP/UDP header |
| 3 | `src_port_ephemeral` | Boolean indicator: $1 \text{ if } \text{src\_port} \ge 1024 \text{ else } 0$ | Source port randomizer |
| 4 | `event_rate_1m` | Events observed from source IP within rolling 60-second window: $N_{60}(IP)$ | Temporal sliding window |
| 5 | `burst_rate_10s` | Maximum events from source IP within any 10-second sub-window | High-frequency burstiness |
| 6 | `inter_arrival_mean` | Sample mean of inter-arrival time deltas: $\bar{\Delta t} = \frac{1}{k-1}\sum (t_i - t_{i-1})$ | Inter-packet delay |
| 7 | `inter_arrival_std` | Standard deviation of inter-packet timing: $\sigma_{\Delta t}$ (measures automation) | Mechanical bot detection |
| 8 | `packet_size_variance` | Variance of packet lengths over source IP session: $s_L^2$ | Payload padding / tunneling |
| 9 | `payload_entropy` | Shannon entropy of payload byte distribution: $H(X) = -\sum p_i \log_2(p_i)$ | Encrypted / shell / text |
| 10 | `unique_dst_ips` | Cardinality of distinct internal destination IPs probed: $\|\text{unique}(\text{dst\_ips})\|$ | Lateral scanning |
| 11 | `unique_dst_ports` | Cardinality of distinct target ports probed: $\|\text{unique}(\text{dst\_ports})\|$ | Service reconnaissance |

### Explicit Invariance & Leakage Rules:
- **STRICTLY PROHIBITED:** `threat_score`, `is_malicious`, `malicious_flag_ratio`, and `attack_type`.
- No feature may depend on model predictions, human security analyst tags, or ground truth labels.
- All 12 dimensions are computable in real-time from raw network socket events and in-memory rolling buffers.

---

## 3. Standardized Machine Learning Pipeline Architecture

### 3.1 Model Encapsulation Contract
All models must be packaged as scikit-learn `Pipeline` objects bundling pre-processing and classification:
```python
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

production_pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("classifier", RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    ))
])
```
- **Guaranteed Invariance:** The model can never receive unscaled features at runtime; `StandardScaler.transform` is automatically executed inside `pipeline.predict_proba(X)`.

### 3.2 Calibrated Ensemble Architecture
1. **Supervised Random Forest Probability:**
   $$P_{\text{RF}} = \text{pipeline.predict_proba}(X)[:, 1] \in [0.0, 1.0]$$
2. **Calibrated Isolation Forest Anomaly Probability:**
   - Raw decision function: $s(x) \in [-\infty, +\infty]$.
   - Min-Max Robust Inversion:
     $$S_{\text{IF}}(x) = 1.0 - \frac{s(x) - s_{\min}}{s_{\max} - s_{\min} + 10^{-9}}$$
     where $s_{\min}, s_{\max}$ are fitted calibration percentiles (1st and 99th percentiles) learned on training folds.
3. **Optimized Blended Score:**
   $$S_{\text{composite}} = w_{\text{RF}} \cdot P_{\text{RF}} + (1 - w_{\text{RF}}) \cdot S_{\text{IF}}$$
   where $w_{\text{RF}} = 0.85, w_{\text{IF}} = 0.15$ is verified via grid search on held-out validation data.

---

## 4. Remediated Campaign Correlation (DBSCAN) Pipeline

### 4.1 Feature Transformation for Clustering
Raw timestamps and ports are eliminated. DBSCAN clusters events based on **normalized behavioral signatures**:
$$\mathbf{z} = \text{RobustScaler().fit_transform}\left(\left[ \log(1 + \text{rate}), \text{port\_entropy}, \text{timing\_variance}, \text{payload\_entropy} \right]\right)$$

### 4.2 Automated Hyperparameter Estimation
1. **`min_samples`:** Fixed at $k = 4$ (minimum events required to constitute a correlated campaign).
2. **`eps` Estimation:** Derived via automated $k$-nearest neighbors distance elbow computation:
   $$\text{eps} = \text{kNN\_distance\_elbow}(X, k=4)$$
3. **Partition Verification:** Validate that:
   - Distinct attack campaigns (SSH Brute Force vs. Web SQLi vs. Port Scan vs. Exfiltration) form separate clusters ($ARI \ge 0.70$).
   - Noise percentage is bounded ($< 25\%$).
   - Benign noise does not form false attack clusters.

---

## 5. Unified Threat Scoring & Threshold Contract

A single, centralized configuration module `backend/ml/config/thresholds.py` governs all decision boundaries across both synchronous APIs and background workers:

```python
THREAT_THRESHOLDS = {
    "CRITICAL": 0.80,   # Block immediately, auto-generate Sentinel playbook, trigger PCAP
    "HIGH":     0.60,   # Alert SOC, generate Sentinel playbook, trigger PCAP
    "MEDIUM":   0.40,   # Log suspicious activity, increment IP risk accumulator
    "LOW":      0.00    # Allow / benign telemetry
}

ENFORCEMENT_DECISIONS = {
    "BLOCK": 0.80,
    "ALERT": 0.50,
    "ALLOW": 0.00
}
```

---

## 6. Execution Roadmap for Implementation (Phases 9–16)

```
[Phase 9: Synthetic Dataset Remediation]
     │   • Generate 5,000-sample clean dataset (DS-REMED) with overlapping distributions
     │   • Guarantee zero single-feature separability (all features < 85% single accuracy)
     ▼
[Phase 10: Unified Feature Pipeline Implementation]
     │   • Build production CleanFeatureExtractor with thread-safety locks
     │   • Remove circular threat_score and malicious_flag_ratio leakage
     ▼
[Phase 11: Model Re-training & Calibration]
     │   • Train Pipeline(StandardScaler + RF) on DS-REMED
     │   • Calibrate Isolation Forest anomaly scores
     │   • Register clean production checkpoint AttackClassifier_Enhanced_v1.0.0.pkl
     ▼
[Phase 12: Remediated Campaign Clustering]
     │   • Implement RobustScaler + DBSCAN in campaign_clustering.py
     │   • Validate clean campaign separation (ARI >= 0.70, noise < 25%)
     ▼
[Phase 13: Runtime Backend Integration]
     │   • Fix missing 'import os' in threat_scoring_service.py
     │   • Fix TypeError crash in explainability.py
     │   • Unify threshold mappings across services
     ▼
[Phase 14: Comprehensive Verification Test Suite]
     │   • Implement true autonomous E2E pipeline test without DB intervention
     │   • Unit test feature extraction, thread safety, and SHAP explanations
     ▼
[Phase 15: Legitimate Statistical Revalidation]
     │   • Execute ACTUAL N=30 repeated autonomous pipeline runs
     │   • Calculate legitimate Fisher's Exact / McNemar and Wilcoxon tests
     ▼
[Phase 16: Publication Readiness & Artifact Delivery]
         • Generate Model Card, Dataset Card, updated Research Tables
         • Ensure 100% provenance and zero fabricated statistics
```
