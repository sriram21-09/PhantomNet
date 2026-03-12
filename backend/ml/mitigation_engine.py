import ipaddress

class MitigationEngine:
    """
    Refines anomaly detection predictions to reduce False Positives.
    Implements whitelisting and threshold-based filtering.
    """
    
    def __init__(self, internal_subnet: str = "192.168.1.0/24", anomaly_threshold: float = -0.1):
        self.internal_subnet = ipaddress.ip_network(internal_subnet)
        self.anomaly_threshold = anomaly_threshold
        # Known safe internal ports
        self.safe_ports = {22, 80, 443}

    def refine_prediction(self, event: dict, initial_pred: int, score: float) -> tuple:
        """
        Applies mitigation logic to the initial model prediction.
        Returns (refined_pred, refined_label)
        Refined Pred: -1 (Anomaly), 1 (Normal)
        """
        src_ip = event.get("src_ip", "0.0.0.0")
        dst_port = int(event.get("dst_port", 0))
        
        # 1. Internal Whitelisting Logic
        try:
            ip_obj = ipaddress.ip_address(src_ip)
            if ip_obj in self.internal_subnet:
                if dst_port in self.safe_ports:
                    # Overrule model if it's internal traffic on standard ports
                    return 1, "BENIGN (Whitelisted)"
        except ValueError:
            pass

        # 2. Threshold Sensitivity Adjustment
        # If score is very close to zero, it's likely a weak anomaly/near-normal event
        if initial_pred == -1 and score > self.anomaly_threshold:
            return 1, "BENIGN (Threshold Adjusted)"

        # 3. Default to model prediction
        label = "MALICIOUS" if initial_pred == -1 else "BENIGN"
        return initial_pred, label
