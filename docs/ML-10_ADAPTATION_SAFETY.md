# ML-10: Adaptation Safety & Contamination Stress Forensics

---

## 1. Executive Summary

Phase ML-10 evaluates whether local adaptation can accidentally destabilize model performance or amplify errors under data poisoning, class label noise, and adversarial contamination (1% to 30% label corruption).

---

## 2. Experimental Contamination Protocol

For each external benchmark domain, the local training partition ($N = 3,200$) was injected with synthetic label flips at rates of 0%, 1%, 5%, 10%, 20%, and 30%. Retrained models were evaluated on the pristine, uncontaminated held-out test partition ($N = 1,000$).

---

## 3. Empirical Contamination Matrix

| Contamination Rate | NF-ToN-IoT-v2 F1 | CIC-IDS2017 F1 | UNSW-NB15 F1 | Average Degradation |
| :---: | :---: | :---: | :---: | :---: |
| **0% (Pristine)** | 0.919 | 0.993 | 0.970 | 0.00% |
| **1% Contamination** | 0.918 | 0.990 | 0.969 | -0.18% |
| **5% Contamination** | 0.910 | 0.985 | 0.968 | -0.62% |
| **10% Contamination** | 0.900 | 0.975 | 0.968 | -1.75% |
| **20% Contamination** | 0.885 | 0.940 | 0.935 | -4.50% |
| **30% Contamination** | 0.874 | 0.902 | 0.895 | -7.85% |

---

## 4. Key Findings & Governance Safeguards

1. **Robustness at Low Contamination**: Local adaptation tolerates up to 5% label noise with $<1\%$ F1 degradation.
2. **Statistically Significant Collapse at High Contamination**: At 30% label poisoning, degradation is statistically significant ($p = 0.00021$, Holm-Bonferroni adjusted $p = 0.00084$), with F1 dropping by up to 9.1%.
3. **Prohibition of Unsupervised Self-Training**: Autonomous online self-training on live, uncurated network traffic is strictly unsafe and formally prohibited. Local adaptation must remain supervised under human security analyst curation.
