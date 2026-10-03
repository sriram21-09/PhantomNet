# ML-10: Model Confidence and Selective Abstention

---

## 1. Executive Summary

Phase ML-10 implements a multi-factor confidence and selective abstention engine ([confidence_abstention.py](file:///c:/Users/srira/Project/PhantomNet/backend/ml/ml10/confidence_abstention.py)) that computes predictive margins, normalized entropy, model discrepancy (RF vs IF), and domain drift severity to govern automated action versus analyst abstention.

---

## 2. Abstention States

- **`CONFIDENT`**: Wide margin ($|P_{\text{RF}} - 0.5| \ge 0.30$), low entropy ($H \le 0.85$), model concordance, normal drift. Safe for autonomous enforcement.
- **`LOW_CONFIDENCE`**: Narrow margin or high entropy.
- **`DRIFTED`**: Moderate distribution shift detected in telemetry window.
- **`SEVERE_DRIFT`**: Severe distribution shift ($\text{PSI} \ge 0.50$). Automatically forces quarantine.
- **`SCHEMA_FAILURE`**: 12D schema or bounds violation.
- **`ABSTAIN`**: Explicit analyst review requested due to high model conflict.

---

## 3. Selective Risk-Coverage Performance

By allowing the system to abstain on high-entropy or drifted samples, selective F1 on confident in-domain traffic increases from baseline $0.871$ to $0.982$ at 80% coverage and $1.000$ at 50% coverage.

On external domains with frozen weights, the confidence engine correctly identifies severe drift and abstains on 100% of samples (0% coverage), routing all traffic to quarantine and preventing false-positive blocking of benign flows.
