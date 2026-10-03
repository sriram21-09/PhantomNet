# PhantomNet Phase ML-7: Generalization & External Validity Audit

**Document Version:** 1.0.0  
**Phase:** ML-7 (Independent Validation, Robustness, Generalization & Publication-Readiness Forensics)  
**Effective Date:** 2026-10-02  
**Status:** COMPLETE AUDIT RECORD

---

## 1. Executive Forensic Finding: Data Availability

```
============================================================
EXTERNAL DATASET AUDIT VERDICT:
NO_INDEPENDENT_DATA_AVAILABLE
============================================================
```

A comprehensive inventory of all 71 CSV datasets across the PhantomNet repository confirmed that:
1. No external public network intrusion benchmark (e.g. CIC-IDS2017, UNSW-NB15, TON_IoT, BoT-IoT) is integrated into the active evaluation pipeline.
2. No physical raw PCAP capture from live enterprise or production IoT networks exists in the repository.
3. All historical training and benchmark sets (`data/remediated_dataset_v3.csv`, `backend/ml/datasets/labeled_events_remediated.csv`, `backend/ml/datasets/labeled_events_v2_enhanced.csv`) originate from mathematical synthetic generators.

---

## 2. Generalization Audit Matrix

| Research Dimension | Evaluated Setting | Empirical Observation | Scientific Validity Classification |
| :--- | :--- | :--- | :--- |
| **In-Distribution Generalization** | Held-Out 20% Partition ($1,000$ samples) from canonical benchmark | F1: $0.865$, Accuracy: $0.928$, Precision: $0.987$, FPR: $0.004$, ROC-AUC: $0.983$. | **SUPPORTED (IN-DISTRIBUTION ONLY)** |
| **Covariate Shift Generalization** | Volumetric traffic amplification (`SCEN-01`) | F1: $0.842$, Recall: $0.741$, FPR: $0.008$. Slight degradation ($\Delta F_1 = -0.023$). | **CONDITIONALLY SUPPORTED** |
| **Stealth Timing Shift** | Low-and-slow evasion timing (`SCEN-02`) | F1: $0.781$, Recall: $0.672$, FPR: $0.012$. Significant recall degradation ($\Delta \text{Recall} = -0.098$). | **CONDITIONALLY SUPPORTED** |
| **Heavy-Tail Payload Shift** | Pareto payload distribution ($\alpha=1.8$) (`SCEN-03`) | F1: $0.748$, Recall: $0.625$, FPR: $0.016$. Severe degradation ($\Delta F_1 = -0.117$). | **NOT SUPPORTED (VULNERABLE TO HEAVY-TAIL EVASION)** |
| **Bimodal Jitter Shift** | Proxy delay timing jitter (`SCEN-04`) | F1: $0.793$, Recall: $0.690$, FPR: $0.010$. Timing features lose discriminative power. | **CONDITIONALLY SUPPORTED** |
| **Protocol Mix Drift** | UDP/ICMP dominance (`SCEN-05`) | F1: $0.812$, Recall: $0.710$, FPR: $0.009$. | **CONDITIONALLY SUPPORTED** |
| **Reconnaissance Shift** | Wide horizontal IP scanning (`SCEN-06`) | F1: $0.884$, Recall: $0.815$, FPR: $0.006$. Scanning signals are amplified and readily detected. | **SUPPORTED** |
| **Encryption/Tunneling Shift**| Elevated payload entropy ($7.4$) (`SCEN-07`) | F1: $0.852$, Recall: $0.760$, FPR: $0.007$. High entropy remains an effective malicious indicator. | **SUPPORTED** |
| **Measurement Noise** | $\pm 15\%$ Gaussian sensor noise (`SCEN-08`) | F1: $0.835$, Recall: $0.735$, FPR: $0.009$. Models show reasonable resilience to noise. | **SUPPORTED** |
| **Telemetry Loss** | $10\%$ feature dropout (`SCEN-09`) | F1: $0.819$, Recall: $0.712$, FPR: $0.011$. Zero-imputation induces moderate recall penalty. | **CONDITIONALLY SUPPORTED** |
| **Rare Attack Prior Shift** | 95% benign / 5% attack (`SCEN-10`) | Precision drops from $0.987$ to $0.782$; false discovery rate increases significantly. | **REQUIRES OPERATIONAL QUALIFICATION** |
| **Attack Storm Prior Shift** | 50% benign / 50% attack (`SCEN-11`) | F1: $0.879$, Recall: $0.792$, Precision: $0.989$. High threat density improves precision. | **SUPPORTED** |
| **Compound Multi-Stress** | All shifts combined (`SCEN-12`) | F1: $0.720$, Recall: $0.582$, FPR: $0.021$. Maximum performance degradation ($\Delta F_1 = -0.145$). | **NOT SUPPORTED (BREAKDOWN UNDER COMPOUND SHIFT)** |
| **Real-World Enterprise Tap** | Physical campus / datacenter network tap | Not evaluated in repository. Zero physical traces present. | **UNTESTED** |

---

## 3. Generalization Verdict

1. **In-Distribution Synthetic Generalization:** **VERIFIED**. On the canonical distribution family, the model reproduces high accuracy ($>92\%$) and low false-positive rates ($<0.5\%$).
2. **Synthetic Out-of-Distribution Robustness:** **PARTIALLY SUPPORTED**. The model retains reasonable detection ($F_1 > 0.80$) under traffic volume, reconnaissance, encryption, and sensor noise shifts. However, it experiences material degradation ($F_1 \approx 0.72 - 0.75$, recall drops to $\approx 58\% - 62\%$) under heavy-tailed payload distributions, stealth evasion timing, and compound multi-stress conditions.
3. **External Real-World Validity:** **UNTESTED**. The repository lacks physical network data; publication claims of "proven real-world generalization" are scientifically unsupported and must be qualified.
