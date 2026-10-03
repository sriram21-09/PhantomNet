# ML-10: Distribution Drift Monitoring Forensics

---

## 1. Executive Summary

Phase ML-10 evaluates distribution drift monitoring across streaming and batch network telemetry. Using Population Stability Index (PSI), scale-normalized Wasserstein distance, and Kolmogorov-Smirnov (KS) two-sample tests against a fixed reference baseline (Synthetic Train $N = 3,200$), the monitoring engine reliably detects moderate and severe distribution shift.

---

## 2. Drift Severity Thresholds

- **`NORMAL`**: Composite $\text{PSI} < 0.10$. Traffic exhibits typical in-domain variance.
- **`MILD`**: $0.10 \le \text{PSI} < 0.25$. Minor distributional perturbation; monitoring logs alert.
- **`MODERATE`**: $0.25 \le \text{PSI} < 0.50$. Substantial distribution shift; requires adaptation review.
- **`SEVERE`**: $\text{PSI} \ge 0.50$ or $\ge 6$ individual features severely drifted. Automatic policy trigger to quarantine and abstain from automated blocking.

---

## 3. Empirical Domain Shift Results

| Domain | Composite PSI | Severity | Flagged Features Count | Top Drifted Features |
| :--- | :---: | :---: | :---: | :--- |
| **Synthetic Test (In-Domain)** | 0.000 | `NORMAL` | 0 | None |
| **Synthetic Mild Noise** | 0.082 | `NORMAL` | 0 | None |
| **NF-ToN-IoT-v2** | 2.622 | `SEVERE` | 10 | `dst_port_class`, `event_rate_1m`, `packet_length` |
| **CIC-IDS2017** | 1.578 | `SEVERE` | 10 | `burst_rate_10s`, `packet_size_variance`, `inter_arrival_mean` |
| **UNSW-NB15** | 2.154 | `SEVERE` | 10 | `unique_dst_ips`, `packet_length`, `payload_entropy` |

---

## 4. Drift-to-Performance Linkage

Spearman rank correlation between composite PSI and frozen canonical model ROC-AUC is $r = -0.985$ ($p = 0.0008$, Holm-Bonferroni adjusted $p = 0.0024$).

Severe distribution drift empirically predicts model discriminative collapse ($\text{ROC-AUC} \le 0.35$). Automated drift monitoring serves as an essential safety alarm to halt uncurated enforcement.
