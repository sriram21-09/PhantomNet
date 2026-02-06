# Decision Logic Design Description

## Purpose
The purpose of the Decision Logic component is to provide a deterministic, rule-based engine that converts machine learning predictions, anomaly scores, and threat intelligence scores into actionable system responses. This component acts as the usage policy enforcement layer, ensuring that automated responses are proportional to the confidence and severity of the detecting signals.

## Inputs
The decision engine accepts four standardized inputs:

| Name            | Type  | Range      | Source              | Description                                                                 |
|-----------------|-------|------------|---------------------|-----------------------------------------------------------------------------|
| `prediction`    | int   | `{0, 1}`   | ML Classifier       | The binary classification output (0 = Benign, 1 = Attack).                  |
| `confidence`    | float | `0.0-1.0`  | ML Classifier       | The probability confidence associated with the prediction (e.g., probability of class 1). |
| `anomaly_score` | float | `0.0-1.0`  | Anomaly Engine      | A score indicating how compliant the traffic is with normal baseline behavior. |
| `threat_score`  | float | `0.0-1.0`  | Correlation Layer   | A normalized score derived from external threat intelligence or heuristic correlations. |

## Decision Tree Logic

The decision logic follows a hierarchical structure to determine the response. The logic is evaluated in order of severity/specificity.

### Threshold Definitions
- **LOW_THRESHOLD**: 0.3
- **MEDIUM_CONFIDENCE**: 0.6
- **MEDIUM_THRESHOLD**: 0.5
- **HIGH_CONFIDENCE**: 0.8
- **HIGH_THRESHOLD**: 0.8

### Logic Flow

1. **Evaluation of Benign Traffic**:
   - IF `prediction == 0` (Benign)
   - AND `anomaly_score < LOW_THRESHOLD`
   - **RETURN: LOG**

2. **Evaluation of Low-Confidence Attacks**:
   - IF `prediction == 1` (Attack)
   - AND `confidence < MEDIUM_CONFIDENCE`
   - **RETURN: THROTTLE**
   - *Rationale: The model flags it, but confidence is low. Aggressive blocking might cause false positives.*

3. **Evaluation of High-Severity Attacks (Block Condition)**:
   - IF `prediction == 1` (Attack)
   - AND `confidence >= HIGH_CONFIDENCE`
   - AND `anomaly_score >= HIGH_THRESHOLD`
   - AND `threat_score >= HIGH_THRESHOLD`
   - **RETURN: BLOCK**
   - *Rationale: All signals align (ML, Anomaly, Threat Intel) at high levels. Immediate blocking is warranted.*

4. **Evaluation of Confirmed Attacks (Deception Condition)**:
   - IF `prediction == 1` (Attack)
   - AND `confidence >= MEDIUM_CONFIDENCE`
   - AND `anomaly_score >= MEDIUM_THRESHOLD`
   - **RETURN: DECEIVE**
   - *Rationale: Confidence is decent and anomalous behavior is observed. Redirect to honeypot to gather intelligence.*

5. **Default Fallback**:
   - IF none of the above specific specific conditions are met exactly (e.g., `prediction=0` but `anomaly_score` high, or `prediction=1` with high confidence but low anomaly):
   - **RETURN: LOG** (or THROTTLE dependent on safety policy, currently defaulting to LOG/THROTTLE based on implementation details).
   - *Final Default for Implementation: `LOG`*

## Response Categories

| Response | Meaning | Intent |
|----------|---------|--------|
| **LOG** | Observe only | Record the event for auditing but take no interference action. Used for benign traffic or ambiguous signals. |
| **THROTTLE** | Rate-limit attacker | Slow down the connection. Used when a threat is suspected (low confidence) or to mitigate potential DoS without full blocking. |
| **DECEIVE** | Redirect to honeypot | Reroute traffic to a controlled environment. Used for confident threats where observing attacker behavior is valuable. |
| **BLOCK** | Firewall / Deny | Terminate the connection immediately. Reserved for high-confidence, high-severity threats. |

## Extensibility
To add future responses:
1. Update the `Response` enum/constants in the codebase.
2. Add the new response type to `backend/ml/response_mapping.py`.
3. Add a new logic branch in the `ResponseDecisionTree` class in `backend/ml/decision_tree.py`.
4. Update this documentation to reflect the new rule.
