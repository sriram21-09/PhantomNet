# PhantomNet Phase ML-6: Threshold & Calibration Normative Specification

**Specification Version:** 1.0.0  
**Effective Date:** 2026-10-02  
**Audit Baseline:** ML-1 through ML-5 Verified Baselines  
**Canonical Schema:** `12D-v1` (12 Canonical Network Flow Features)  
**Status:** NORMATIVE

---

## 1. Executive Principle & Firewall Guarantee

This specification establishes the authoritative rules governing threat scoring, probability calibration, decision thresholds, and empirical validation within PhantomNet.

> [!IMPORTANT]
> **Test-Set Firewall Axiom:**
> No data from any held-out evaluation or test set shall influence model parameters, scaling transformations, calibration parameters, or threshold selections. All preprocessing, model training, calibration fitting, and threshold selection must be conducted strictly on training and development partitions.

---

## 2. Canonical Architecture & Threat-Scoring Contract

### 2.1 Feature Contract
All models and inference pipelines MUST strictly consume the authoritative 12-dimensional canonical schema (`12D-v1`) in exact index order:
1. `packet_length`
2. `protocol_encoding`
3. `dst_port_class`
4. `src_port_ephemeral`
5. `event_rate_1m`
6. `burst_rate_10s`
7. `inter_arrival_mean`
8. `inter_arrival_std`
9. `packet_size_variance`
10. `payload_entropy`
11. `unique_dst_ips`
12. `unique_dst_ports`

Any checkpoint with non-12 dimensions (e.g. 6D, 13D, 15D, 32D) or discordant feature names is strictly **QUARANTINED** from production inference.

### 2.2 Canonical Hybrid Formulation
The single authoritative hybrid threat scoring formula is:

$$S_{\text{composite}} = w_{\text{rf}} \cdot P_{\text{RF}} + w_{\text{if}} \cdot S_{\text{IF}}$$

$$S_{\text{composite}} = 0.85 \cdot P_{\text{RF}} + 0.15 \cdot S_{\text{IF}}$$

- $P_{\text{RF}} \in [0.0, 1.0]$: Supervised Random Forest posterior probability of attack.
- $S_{\text{IF}} \in [0.0, 1.0]$: Directionally calibrated Isolation Forest anomaly evidence.
- $S_{\text{composite}} \in [0.0, 1.0]$: Final composite threat score.

> [!NOTE]
> **Score Semantics:** $S_{\text{composite}}$ is an **ordinal threat score**, NOT a calibrated Bayes probability of attack. It reflects combined supervised attack signature confidence and unsupervised behavioral deviation.

---

## 3. Isolation Forest Calibration Protocol

### 3.1 Raw Signal Inversion
Scikit-learn's `IsolationForest.decision_function(x)` yields positive values ($s > 0$) for nominal inliers and negative values ($s < 0$) for anomalous outliers. To directionally align with threat evidence:

$$S_{\text{IF}}(x) = \text{clip}\left(1.0 - \frac{s(x) - s_{\min}}{s_{\max} - s_{\min} + 10^{-9}},\, 0.0,\, 1.0\right)$$

### 3.2 Leakage-Safe Parameter Derivation
Under Phase ML-6 protocol:
- $s_{\min}$ and $s_{\max}$ MUST be estimated exclusively from the **Development / Calibration** partition (or training distribution).
- **Prohibition:** Neither $s_{\min}$ nor $s_{\max}$ shall ever be computed over the test set or full dataset prior to splitting.
- **Production Reference Bounds:** For backward-compatible standalone inference when dynamic development sets are unavailable, the frozen reference bounds are $s_{\min} = -0.181713$ and $s_{\max} = +0.166857$.

---

## 4. Decision & Severity Thresholds

### 4.1 Automated Enforcement Actions
Enforcement routing maps composite threat score $S_{\text{composite}}$ directly to policy actions:

| Action | Score Threshold | Operational Meaning |
| :--- | :--- | :--- |
| **BLOCK** | $S_{\text{composite}} \ge 0.80$ | Automated inline mitigation; firewall drop or host isolation |
| **ALERT** | $0.50 \le S_{\text{composite}} < 0.80$ | High-priority security analyst escalation / SIEM alert |
| **ALLOW** | $S_{\text{composite}} < 0.50$ | Traffic permitted without active intervention |

### 4.2 Threat Severity Classification
Threat severity stratification maps composite threat score $S_{\text{composite}}$:

| Severity Level | Score Range | Operational SLA |
| :--- | :--- | :--- |
| **CRITICAL** | $S_{\text{composite}} \ge 0.80$ | Immediate automated response (< 50 ms) |
| **HIGH** | $0.60 \le S_{\text{composite}} < 0.80$ | Analyst triage required within 15 minutes |
| **MEDIUM** | $0.40 \le S_{\text{composite}} < 0.60$ | Routine triage within 2 hours |
| **LOW** | $S_{\text{composite}} < 0.40$ | Telemetry logging and behavioral profiling |

---

## 5. Development Threshold-Selection Protocol

When empirical threshold optimization is conducted:
1. **Partition Structure:**
   - 64% Training Partition (Model fitting)
   - 16% Development / Calibration Partition (Threshold search & calibration)
   - 20% Held-out Final Test Partition (Single evaluation post-freeze)
2. **Search Grid:** $T \in [0.01, 0.99]$ with increment $\Delta T = 0.01$.
3. **Objective Function:** $\arg\max_T F_1(y_{\text{dev}}, \hat{y}(T))$ or $\arg\max_T \text{BalancedAccuracy}(y_{\text{dev}}, \hat{y}(T))$.
4. **Tie-Breaking Rule:** The median threshold value among tied candidates is selected.
5. **Freeze Rule:** Thresholds are permanently frozen prior to evaluating the held-out test partition.

---

## 6. Prohibited Practices

1. No evaluation of test sets during hyperparameter, calibration, or threshold tuning.
2. No modification of canonical weights ($w_{\text{rf}}=0.85, w_{\text{if}}=0.15$) without formal governance approval.
3. No misrepresentation of composite scores as "calibrated probabilities" without empirical calibration evidence.
4. No modification of feature dimensionality or order.
