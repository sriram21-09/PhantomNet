import re

class SignatureEngine:
    def __init__(self):
        # Regex patterns for known attacks
        self.sql_injection = re.compile(r"(UNION|SELECT|DROP|INSERT|DELETE|UPDATE|--)", re.IGNORECASE)
        self.xss_attack = re.compile(r"(<script>|javascript:|onerror=|onload=)", re.IGNORECASE)
        self.path_traversal = re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE)

    def check_signatures(self, log_entry):
        """
        Returns a list of matched signature names and a risk score.
        """
        detected = []
        risk_score = 0
        
        service = log_entry.get("service_type", "").upper()
        payload = log_entry.get("payload", "")
        status = log_entry.get("status", "")

        # --- SSH SIGNATURES ---
        if service == "SSH":
            if status == "Failed":
                detected.append("SSH_AUTH_FAILURE")
                risk_score += 20 # Bumped from 10
            if log_entry.get("command_count", 0) > 20:
                detected.append("SSH_HIGH_ACTIVITY")
                risk_score += 30 # Bumped from 20

        # --- HTTP SIGNATURES ---
        elif service == "HTTP":
            if self.sql_injection.search(payload):
                detected.append("HTTP_SQL_INJECTION")
                risk_score += 100 # 🚨 CRITICAL (Was 50)
            if self.xss_attack.search(payload):
                detected.append("HTTP_XSS_ATTEMPT")
                risk_score += 80  # 🚨 HIGH (Was 40)
            if self.path_traversal.search(payload):
                detected.append("HTTP_PATH_TRAVERSAL")
                risk_score += 80  # 🚨 HIGH (Was 45)
            if log_entry.get("url_count", 0) > 50:
                 detected.append("HTTP_SCANNER_BEHAVIOR")
                 risk_score += 30

        # --- FTP SIGNATURES ---
        elif service == "FTP":
            if "RETR" in payload and log_entry.get("payload_size", 0) > 5000:
                detected.append("FTP_DATA_EXFILTRATION")
                risk_score += 60

        # --- SMTP SIGNATURES ---
        elif service == "SMTP":
            if log_entry.get("payload_size", 0) > 2000:
                detected.append("SMTP_LARGE_PAYLOAD") 
                risk_score += 40

        return detected, risk_score
