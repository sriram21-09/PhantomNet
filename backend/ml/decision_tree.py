from typing import Dict, Any

class ResponseDecisionTree:
    """
    A deterministic, stateless decision tree that converts ML signals into 
    system responses (LOG, THROTTLE, DECEIVE, BLOCK).
    """

    # Default Thresholds
    DEFAULT_THRESHOLDS = {
        "LOW_THRESHOLD": 0.3,
        "MEDIUM_CONFIDENCE": 0.6,
        "MEDIUM_THRESHOLD": 0.5,
        "HIGH_CONFIDENCE": 0.8,
        "HIGH_THRESHOLD": 0.8
    }

    def __init__(self, thresholds: Dict[str, float] = None):
        """
        Initialize the decision tree with custom or default thresholds.
        
        Args:
            thresholds (dict, optional): Dictionary covering threshold keys. 
                                         Defaults to DEFAULT_THRESHOLDS.
        """
        self.thresholds = self.DEFAULT_THRESHOLDS.copy()
        if thresholds:
            self.thresholds.update(thresholds)

    def decide(self, *, prediction: int, confidence: float, anomaly_score: float, threat_score: float) -> str:
        """
        Execute the decision logic based on input signals.

        Args:
            prediction (int): 0 (Benign) or 1 (Attack).
            confidence (float): Model confidence (0.0 - 1.0).
            anomaly_score (float): Anomaly detection score (0.0 - 1.0).
            threat_score (float): Threat intelligence score (0.0 - 1.0).

        Returns:
            str: One of "LOG", "THROTTLE", "DECEIVE", "BLOCK".
        """
        
        # Load thresholds for readability
        LOW_THRESHOLD = self.thresholds["LOW_THRESHOLD"]
        MEDIUM_CONFIDENCE = self.thresholds["MEDIUM_CONFIDENCE"]
        MEDIUM_THRESHOLD = self.thresholds["MEDIUM_THRESHOLD"]
        HIGH_CONFIDENCE = self.thresholds["HIGH_CONFIDENCE"]
        HIGH_THRESHOLD = self.thresholds["HIGH_THRESHOLD"]

        # 1. Logic for Benign Prediction
        if prediction == 0:
            if anomaly_score < LOW_THRESHOLD:
                return "LOG"
            # If prediction is 0 but anomaly is high, we default to LOG 
            # (or could escalate, but per spec we stick to LOG for benign-ish)
            return "LOG"

        # 2. Logic for Attack Prediction
        if prediction == 1:
            # Low Confidence -> Throttle
            if confidence < MEDIUM_CONFIDENCE:
                return "THROTTLE"

            # High Confidence + High Anomaly + High Threat -> Block
            # (Check this first as it is the most specific/severe)
            if (confidence >= HIGH_CONFIDENCE 
                and anomaly_score >= HIGH_THRESHOLD 
                and threat_score >= HIGH_THRESHOLD):
                return "BLOCK"

            # Medium Confidence + Medium Anomaly -> Deceive
            if (confidence >= MEDIUM_CONFIDENCE 
                and anomaly_score >= MEDIUM_THRESHOLD):
                return "DECEIVE"

            # Fallback for Prediction=1 if no specific severe condition met
            # e.g. High confidence but very low anomaly score
            return "THROTTLE"
        
        # Default safety fallback
        return "LOG"
