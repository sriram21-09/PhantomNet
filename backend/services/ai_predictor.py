class ThreatDetector:
    """
    Placeholder AI threat scoring engine.
    Real ML model will be plugged in during Week 3.
    """

    def predict(self, features):
        """
        Input: feature vector (list of floats)
        Output: (label, threat_score)
        """
        # Simple rule-based placeholder
        threat_score = 0.7 if sum(features) > 1 else 0.2
        label = "malicious" if threat_score > 0.5 else "benign"

        return label, threat_score