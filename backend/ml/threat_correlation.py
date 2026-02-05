from ml.anomaly_detector import AnomalyDetector
from ml.signatures import SignatureEngine
class ThreatCorrelator:
    def __init__(self):
        self.ai_brain = AnomalyDetector()
        self.rules_engine = SignatureEngine()

        # Load trained ML model if available
        self.ai_brain.load()

        # Mock Threat Intelligence Feed
        self.threat_feed_ips = {
            "192.168.1.100": "KNOWN_BOTNET",
            "10.0.0.50": "TOR_EXIT_NODE",
            "172.16.0.5": "MALICIOUS_SCANNER"
        }

    # 🔹 PRIMARY ANALYSIS METHOD
    def analyze_log(self, log_entry):
        """
        Orchestrates full threat analysis:
        ML anomaly + rule signatures + threat intel
        """

        # 1. AI Anomaly Detection
        ai_pred, ai_score = self.ai_brain.predict(log_entry)

        ai_risk = 0.0
        if ai_pred == -1:
            # Convert anomaly score to risk (0–100)
            ai_risk = abs(ai_score) * 100

        # 2. Signature-Based Detection
        signatures, rule_risk = self.rules_engine.check_signatures(log_entry)

        # 3. Threat Intelligence Lookup
        attacker_ip = log_entry.get("attacker_ip")
        feed_match = self.threat_feed_ips.get(attacker_ip)
        feed_risk = 100.0 if feed_match else 0.0

        # 4. Correlation Logic
        # AI (20%) + Rules (30%) + Intel (50%)
        total_risk_score = (
            (ai_risk * 0.2) +
            (rule_risk * 0.3) +
            (feed_risk * 0.5)
        )

        # 5. Verdict
        if total_risk_score > 80:
            verdict = "CRITICAL"
        elif total_risk_score > 50:
            verdict = "HIGH"
        elif total_risk_score > 20:
            verdict = "WARNING"
        else:
            verdict = "SAFE"

        return {
            "verdict": verdict,
            "total_risk_score": round(total_risk_score, 2),
            "details": {
                "ai_anomaly": ai_pred == -1,
                "ai_score": round(ai_score, 4),
                "signatures_triggered": signatures,
                "threat_intel_match": feed_match
            }
        }

    # 🔹 COMPATIBILITY ALIAS (DO NOT REMOVE)
    def evaluate(self, log_entry):
        """
        Alias for analyze_log() to support existing sniffer code.
        """
        return self.analyze_log(log_entry)
