import json
import random
from backend.ml.anomaly_detector import AnomalyDetector
from backend.ml.signatures import SignatureEngine

class ThreatCorrelator:
    def __init__(self):
        self.ai_brain = AnomalyDetector()
        self.rules_engine = SignatureEngine()
        
        # Load AI Brain if available
        self.ai_brain.load()
        
        # Mock Threat Feed
        self.threat_feed_ips = {
            "192.168.1.100": "KNOWN_BOTNET",
            "10.0.0.50": "TOR_EXIT_NODE",
            "172.16.0.5": "MALICIOUS_SCANNER"
        }

    def analyze_log(self, log_entry):
        """
        Orchestrates the full security analysis.
        Returns a rich 'Threat Object'.
        """
        # 1. AI Analysis
        ai_pred, ai_score = self.ai_brain.predict(log_entry)
        
        # --- FIX: Initialize ai_risk BEFORE the if check ---
        ai_risk = 0.0 
        
        # If AI says it's an anomaly (-1), calculate the risk score
        if ai_pred == -1:
            ai_risk = abs(ai_score) * 100 # Scale to 0-100 roughly

        # 2. Signature Analysis
        signatures, rule_risk = self.rules_engine.check_signatures(log_entry)

        # 3. External Threat Feed Lookup
        ip = log_entry.get("attacker_ip")
        feed_match = self.threat_feed_ips.get(ip)
        feed_risk = 100.0 if feed_match else 0.0

        # 4. Correlation Logic (Refined Weights)
        # AI (0.2) + Rules (0.3) + Feed (0.5)
        total_risk_score = (ai_risk * 0.2) + (rule_risk * 0.3) + (feed_risk * 0.5)

        # 5. Verdict
        verdict = "SAFE"
        if total_risk_score > 80:
            verdict = "CRITICAL"
        elif total_risk_score > 50:
            verdict = "HIGH"
        elif total_risk_score > 20:
            verdict = "WARNING"

        return {
            "verdict": verdict,
            "total_risk_score": round(total_risk_score, 2),
            "details": {
                "ai_anomaly": bool(ai_pred == -1),
                "signatures_triggered": signatures,
                "threat_intel_match": feed_match
            }
        }