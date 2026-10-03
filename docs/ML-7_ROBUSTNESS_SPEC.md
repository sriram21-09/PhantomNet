# PhantomNet Phase ML-7: Robustness Specification & Scenario Definitions

**Document Version:** 1.0.0  
**Phase:** ML-7 (Independent Validation, Robustness, Generalization & Publication-Readiness Forensics)  
**Effective Date:** 2026-10-02  
**Status:** NORMATIVE SPECIFICATION

---

## 1. Objective & Scientific Discipline

This specification establishes the normative criteria for evaluating model robustness under independent synthetic distribution shifts.

> [!IMPORTANT]
> **Independence Principle:**
> Robustness evaluation scenarios MUST NOT reproduce the original training data generator parameters. Scenarios are parameterized using distinct distribution families (e.g. Pareto, Log-normal, Weibull, Gaussian mixtures) to stress model decision boundaries under simulated operational shifts.

---

## 2. Robustness Scenario Taxonomy (12 Scenarios)

All scenarios strictly consume the canonical 12-dimensional feature schema (`12D-v1`) with $N = 1,000$ samples:

| Scenario ID | Scenario Name | Shift Family | Mathematical Mechanism & Parameterization |
| :--- | :--- | :--- | :--- |
| **SCEN-01** | `high_event_rate_flooding` | Covariate Shift (Traffic Volume) | Volumetric traffic amplification: `event_rate_1m` amplified $2.5\times - 4.5\times$, `burst_rate_10s` increased to $50$, `inter_arrival_mean` compressed by $2\times - 4\times$. |
| **SCEN-02** | `low_and_slow_stealth` | Covariate Shift (Evasion Timing) | Stealth attack timing: `event_rate_1m` suppressed by $65\%$, bursts set to $1$, `inter_arrival_mean` stretched by $2.5\times - 5.0\times$ plus $2.0$s offset. |
| **SCEN-03** | `heavy_tailed_packet_sizes` | Distribution Family Shift (Payload Size) | Jumbo frames / data exfiltration: `packet_length` drawn from Pareto distribution ($\alpha = 1.8, x_m = 120$) up to $9,000$ bytes; size variance amplified $2\times - 5\times$. |
| **SCEN-04** | `bimodal_jitter_timing` | Distribution Family Shift (Bimodal Timing) | Multi-hop proxy delay simulation: `inter_arrival_mean` drawn from bimodal mixture ($60\%$ Exp(0.5), $40\%$ Normal(8.0, 1.5)) with variance amplified. |
| **SCEN-05** | `protocol_mix_udp_dominance` | Covariate Shift (Protocol Distribution) | Protocol drift: TCP suppressed ($15\%$), UDP/ICMP dominance ($85\%$, `protocol_encoding=2, 3`), destination port shifted toward DNS/SNMP (`dst_port_class=1`). |
| **SCEN-06** | `wide_subnet_horizontal_scan` | Covariate Shift (Target Diversity) | Horizontal subnet reconnaissance: `unique_dst_ips` amplified up to $30$, `unique_dst_ports` amplified up to $20$. |
| **SCEN-07** | `high_entropy_c2_tunneling` | Distribution Shift (Payload Encryption) | Encrypted C2 / TLS / DNS tunneling: `payload_entropy` elevated to Normal($7.4, 0.35$), clamped to $[6.5, 7.99]$. |
| **SCEN-08** | `sensor_noise_quantization` | Measurement Noise / Telemetry Distortion | Telemetry degradation: $\pm 15\%$ Gaussian sensor noise added to continuous features, followed by coarse integer/decile rounding. |
| **SCEN-09** | `feature_missingness_dropout` | Missing Data (Lossy Telemetry) | Lossy network tap emulation: $10\%$ random dropout across continuous numeric observables, zero-imputed. |
| **SCEN-10** | `class_prior_extreme_rare_attack` | Prior Probability Shift (Rare Attack) | Severe class imbalance: $95\%$ benign ($950$ flows) vs. $5\%$ malicious ($50$ flows), emulating quiet operational networks. |
| **SCEN-11** | `class_prior_attack_storm` | Prior Probability Shift (Attack Storm) | Threat saturation: $50\%$ benign ($500$ flows) vs. $50\%$ malicious ($500$ flows), emulating active DDoS / botnet sweeps. |
| **SCEN-12** | `composite_multivariate_stress` | Compound Multivariate Covariate Shift | Compound stress: simultaneously applies heavy-tailed sizes, bimodal timing jitter, elevated entropy, and sensor noise. |

---

## 3. Strict Execution Firewall

Under Phase ML-7 evaluation:
1. **Model Weights Frozen:** Supervised Random Forest and unsupervised Isolation Forest are fitted once on the 64% Training fold ($3,200$ samples) of `data/remediated_dataset_v3.csv`.
2. **Calibration Frozen:** Isolation Forest calibration bounds ($s_{\min,\text{dev}}, s_{\max,\text{dev}}$) are fitted once on the 16% Development fold ($800$ samples).
3. **Thresholds Frozen:** Thresholds ($\text{BLOCK}=0.80, \text{ALERT}=0.50, T^*_{\text{F1}}$) are determined on the Development fold.
4. **Zero Scenario Fitting:** No scenario data is ever used to adjust scalers, retrain models, update calibration parameters, or select decision thresholds.
