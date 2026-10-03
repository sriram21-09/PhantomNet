"""
PhantomNet Phase ML-10: End-to-End Deployment Governance Pipeline
=================================================================
Coordinates schema gating, drift monitoring, confidence assessment, model inference,
probability calibration, threshold policy enforcement, and audit logging.
"""

from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import time
import numpy as np

from .schema_gate import SchemaGate, SchemaValidationResult, SchemaSeverity
from .drift_monitor import DistributionDriftMonitor, DriftStatus, DriftSeverity
from .confidence_abstention import ConfidenceAbstentionEngine, AbstentionDecision, ConfidenceState
from .calibration_service import CalibrationService
from backend.ml.config.thresholds import RF_WEIGHT, IF_WEIGHT, BLOCK_THRESHOLD, ALERT_THRESHOLD


class GovernanceAction(str, Enum):
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    ABSTAIN = "ABSTAIN"


class GovernanceTelemetryDecision:
    def __init__(
        self,
        action: GovernanceAction,
        raw_composite_score: float,
        calibrated_probability: Optional[float],
        rf_prob: float,
        if_score: float,
        confidence_state: ConfidenceState,
        drift_severity: DriftSeverity,
        schema_severity: SchemaSeverity,
        latency_breakdown_ms: Dict[str, float],
        reasons: List[str]
    ):
        self.action = action
        self.raw_composite_score = raw_composite_score
        self.calibrated_probability = calibrated_probability
        self.rf_prob = rf_prob
        self.if_score = if_score
        self.confidence_state = confidence_state
        self.drift_severity = drift_severity
        self.schema_severity = schema_severity
        self.latency_breakdown_ms = latency_breakdown_ms
        self.reasons = reasons

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "raw_composite_score": float(self.raw_composite_score),
            "calibrated_probability": float(self.calibrated_probability) if self.calibrated_probability is not None else None,
            "rf_prob": float(self.rf_prob),
            "if_score": float(self.if_score),
            "confidence_state": self.confidence_state.value,
            "drift_severity": self.drift_severity.value,
            "schema_severity": self.schema_severity.value,
            "latency_breakdown_ms": {k: float(v) for k, v in self.latency_breakdown_ms.items()},
            "reasons": self.reasons
        }


class DeploymentGovernancePipeline:
    """
    Unified fail-closed deployment safety pipeline for PhantomNet ML.
    """

    def __init__(
        self,
        rf_model: Any,
        if_model: Any,
        scaler: Any,
        drift_monitor: Optional[DistributionDriftMonitor] = None,
        calibration_service: Optional[CalibrationService] = None,
        block_threshold: float = BLOCK_THRESHOLD,
        alert_threshold: float = ALERT_THRESHOLD,
        rf_weight: float = RF_WEIGHT,
        if_weight: float = IF_WEIGHT
    ):
        self.rf_model = rf_model
        self.if_model = if_model
        self.scaler = scaler
        self.schema_gate = SchemaGate(strict_mode=True)
        self.drift_monitor = drift_monitor
        self.confidence_engine = ConfidenceAbstentionEngine()
        self.calibration_service = calibration_service
        self.block_threshold = block_threshold
        self.alert_threshold = alert_threshold
        self.rf_weight = rf_weight
        self.if_weight = if_weight

    def process_telemetry(self, raw_record: Any, override_drift_status: Optional[DriftStatus] = None) -> GovernanceTelemetryDecision:
        """
        Executes full safety pipeline on single telemetry flow.
        """
        latencies = {}
        t0 = time.perf_counter()

        # Step 1: Schema Validation
        t_sch = time.perf_counter()
        schema_res = self.schema_gate.validate_record(raw_record)
        latencies["schema_gate_ms"] = (time.perf_counter() - t_sch) * 1000.0

        if not schema_res.is_admissible or schema_res.sanitized_vector is None:
            latencies["total_ms"] = (time.perf_counter() - t0) * 1000.0
            return GovernanceTelemetryDecision(
                action=GovernanceAction.QUARANTINE,
                raw_composite_score=0.0,
                calibrated_probability=None,
                rf_prob=0.0,
                if_score=0.0,
                confidence_state=ConfidenceState.SCHEMA_FAILURE,
                drift_severity=DriftSeverity.NORMAL,
                schema_severity=schema_res.severity,
                latency_breakdown_ms=latencies,
                reasons=["Schema violation: " + "; ".join(schema_res.messages)]
            )

        vec = schema_res.sanitized_vector.reshape(1, -1)

        # Step 2: Drift Monitoring Check
        t_drift = time.perf_counter()
        if override_drift_status is not None:
            drift_status = override_drift_status
        elif self.drift_monitor:
            drift_status = self.drift_monitor.process_sample(vec)
            if drift_status is None and self.drift_monitor.cached_status is not None:
                drift_status = self.drift_monitor.cached_status
        else:
            drift_status = None
        latencies["drift_monitor_ms"] = (time.perf_counter() - t_drift) * 1000.0
        drift_sev = drift_status.severity if drift_status else DriftSeverity.NORMAL

        # Step 3: Normalization & Model Scoring
        t_inf = time.perf_counter()
        vec_scaled = self.scaler.transform(vec) if self.scaler is not None else vec
        rf_prob = float(self.rf_model.predict_proba(vec_scaled)[0, 1])

        # IF anomaly score: normalizes decision_function output to [0, 1]
        if hasattr(self.if_model, "decision_function"):
            raw_if = float(self.if_model.decision_function(vec_scaled)[0])
            # IF decision_function: higher is normal (>0), lower is anomaly (<0)
            if_score = float(np.clip(0.5 - (raw_if / 0.5), 0.0, 1.0))
        else:
            if_score = 0.5

        # Canonical Composite Score
        composite_score = float(self.rf_weight * rf_prob + self.if_weight * if_score)
        latencies["model_inference_ms"] = (time.perf_counter() - t_inf) * 1000.0

        # Step 4: Confidence & Abstention
        t_conf = time.perf_counter()
        abstention = self.confidence_engine.evaluate(
            rf_prob_attack=rf_prob,
            if_anomaly_score=if_score,
            composite_score=composite_score,
            schema_result=schema_res,
            drift_status=drift_status
        )
        latencies["confidence_check_ms"] = (time.perf_counter() - t_conf) * 1000.0

        # Step 5: Probability Calibration (Optional separate layer)
        t_cal = time.perf_counter()
        cal_prob = None
        if self.calibration_service and self.calibration_service.is_fitted:
            cal_prob = self.calibration_service.predict_probability(rf_prob)
        latencies["calibration_ms"] = (time.perf_counter() - t_cal) * 1000.0

        # Step 6: Policy Action Gating
        t_act = time.perf_counter()
        reasons = list(abstention.reasons)

        if abstention.should_abstain:
            if abstention.state == ConfidenceState.SEVERE_DRIFT:
                action = GovernanceAction.QUARANTINE
            else:
                action = GovernanceAction.ABSTAIN
        elif composite_score >= self.block_threshold:
            action = GovernanceAction.BLOCK
            reasons.append(f"Threat score {composite_score:.3f} exceeds BLOCK threshold {self.block_threshold:.2f}")
        elif composite_score >= self.alert_threshold:
            action = GovernanceAction.ALERT
            reasons.append(f"Threat score {composite_score:.3f} exceeds ALERT threshold {self.alert_threshold:.2f}")
        else:
            action = GovernanceAction.ALLOW

        latencies["policy_gating_ms"] = (time.perf_counter() - t_act) * 1000.0
        latencies["total_ms"] = (time.perf_counter() - t0) * 1000.0

        return GovernanceTelemetryDecision(
            action=action,
            raw_composite_score=composite_score,
            calibrated_probability=cal_prob,
            rf_prob=rf_prob,
            if_score=if_score,
            confidence_state=abstention.state,
            drift_severity=drift_sev,
            schema_severity=schema_res.severity,
            latency_breakdown_ms=latencies,
            reasons=reasons
        )
