"""
PhantomNet Phase ML-10: Model Confidence and Selective Abstention Engine
========================================================================
Calculates predictive uncertainty, margins, entropy, and anomaly signals to govern
automated enforcement versus human/analyst abstention.
"""

from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

from .drift_monitor import DriftStatus, DriftSeverity
from .schema_gate import SchemaValidationResult, SchemaSeverity


class ConfidenceState(str, Enum):
    CONFIDENT = "CONFIDENT"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    DRIFTED = "DRIFTED"
    SEVERE_DRIFT = "SEVERE_DRIFT"
    SCHEMA_FAILURE = "SCHEMA_FAILURE"
    ABSTAIN = "ABSTAIN"


class AbstentionDecision:
    def __init__(
        self,
        state: ConfidenceState,
        should_abstain: bool,
        confidence_score: float,
        margin: float,
        predictive_entropy: float,
        if_anomaly_score: float,
        composite_threat_score: float,
        reasons: List[str]
    ):
        self.state = state
        self.should_abstain = should_abstain
        self.confidence_score = confidence_score
        self.margin = margin
        self.predictive_entropy = predictive_entropy
        self.if_anomaly_score = if_anomaly_score
        self.composite_threat_score = composite_threat_score
        self.reasons = reasons

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "should_abstain": self.should_abstain,
            "confidence_score": float(self.confidence_score),
            "margin": float(self.margin),
            "predictive_entropy": float(self.predictive_entropy),
            "if_anomaly_score": float(self.if_anomaly_score),
            "composite_threat_score": float(self.composite_threat_score),
            "reasons": self.reasons
        }


class ConfidenceAbstentionEngine:
    """
    Evaluates confidence, predictive margin, entropy, and drift state to determine abstention.
    """

    def __init__(
        self,
        min_margin_threshold: float = 0.30,       # P_RF within [0.35, 0.65] is considered uncertain
        max_entropy_threshold: float = 0.85,      # Normalized entropy > 0.85 is high uncertainty
        anomaly_discrepancy_threshold: float = 0.60
    ):
        self.min_margin = min_margin_threshold
        self.max_entropy = max_entropy_threshold
        self.anomaly_discrepancy = anomaly_discrepancy_threshold

    def evaluate(
        self,
        rf_prob_attack: float,
        if_anomaly_score: float,
        composite_score: float,
        schema_result: Optional[SchemaValidationResult] = None,
        drift_status: Optional[DriftStatus] = None
    ) -> AbstentionDecision:
        """
        Evaluates full telemetry inference state for confidence or abstention.
        """
        reasons = []

        # 1. Schema Failure Check
        if schema_result and not schema_result.is_admissible:
            return AbstentionDecision(
                state=ConfidenceState.SCHEMA_FAILURE,
                should_abstain=True,
                confidence_score=0.0,
                margin=0.0,
                predictive_entropy=1.0,
                if_anomaly_score=if_anomaly_score,
                composite_threat_score=composite_score,
                reasons=["Input vector rejected by 12D schema gate."] + schema_result.messages
            )

        # 2. Severe Drift Check
        if drift_status and drift_status.severity == DriftSeverity.SEVERE:
            return AbstentionDecision(
                state=ConfidenceState.SEVERE_DRIFT,
                should_abstain=True,
                confidence_score=0.10,
                margin=abs(rf_prob_attack - 0.5) * 2.0,
                predictive_entropy=self._compute_binary_entropy(rf_prob_attack),
                if_anomaly_score=if_anomaly_score,
                composite_threat_score=composite_score,
                reasons=[f"Traffic domain exhibits severe distribution shift (PSI = {drift_status.composite_psi:.3f})."]
            )

        # Calculate RF Margin: [0.0, 1.0] where 1.0 = completely certain (0 or 1), 0.0 = completely uncertain (0.5)
        margin = float(abs(rf_prob_attack - 0.5) * 2.0)

        # Calculate Normalized Binary Entropy: [0.0, 1.0]
        entropy = float(self._compute_binary_entropy(rf_prob_attack))

        # Model Discrepancy: RF says benign (e.g. 0.05) but IF says highly anomalous (e.g. 0.95)
        model_discrepancy = abs(rf_prob_attack - if_anomaly_score)

        # Confidence Score formula combining margin and consistency
        confidence_score = float(np.clip(margin * (1.0 - 0.5 * entropy) * (1.0 - 0.3 * model_discrepancy), 0.0, 1.0))

        # Determine Abstention State
        if drift_status and drift_status.severity == DriftSeverity.MODERATE:
            state = ConfidenceState.DRIFTED
            should_abstain = True
            reasons.append(f"Moderate distribution shift detected (PSI = {drift_status.composite_psi:.3f}).")

        elif margin < self.min_margin or entropy > self.max_entropy:
            state = ConfidenceState.LOW_CONFIDENCE
            should_abstain = True
            reasons.append(f"Model prediction margin too narrow ({margin:.3f} < {self.min_margin:.3f}) / high entropy ({entropy:.3f}).")

        elif model_discrepancy > self.anomaly_discrepancy:
            state = ConfidenceState.ABSTAIN
            should_abstain = True
            reasons.append(f"Severe RF vs IF model conflict (Discrepancy = {model_discrepancy:.3f}).")

        else:
            state = ConfidenceState.CONFIDENT
            should_abstain = False

        return AbstentionDecision(
            state=state,
            should_abstain=should_abstain,
            confidence_score=confidence_score,
            margin=margin,
            predictive_entropy=entropy,
            if_anomaly_score=if_anomaly_score,
            composite_threat_score=composite_score,
            reasons=reasons
        )

    def _compute_binary_entropy(self, p: float) -> float:
        p = float(np.clip(p, 1e-7, 1.0 - 1e-7))
        q = 1.0 - p
        ent = -(p * np.log2(p) + q * np.log2(q))
        return float(np.clip(ent, 0.0, 1.0))
