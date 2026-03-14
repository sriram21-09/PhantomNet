import re
import logging
from typing import List, Dict, Any, Set
from datetime import datetime

# Setup Logger
logger = logging.getLogger("ioc_extractor")
logger.setLevel(logging.INFO)


class IOCExtractor:
    """
    Service for extracting and classifying Indicators of Compromise (IOCs) from raw event data.
    Supports IPs, Domains, URLs, File Hashes, and Email Addresses.
    """

    # Regex Patterns
    IP_PATTERN = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    DOMAIN_PATTERN = r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"
    URL_PATTERN = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*"
    HASH_MD5 = r"\b[a-fA-F0-9]{32}\b"
    HASH_SHA1 = r"\b[a-fA-F0-9]{40}\b"
    HASH_SHA256 = r"\b[a-fA-F0-9]{64}\b"
    EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

    def __init__(self):
        pass

    def extract_from_text(self, text: str) -> Dict[str, Set[str]]:
        """Extracts all supported IOC types from a given string."""
        if not text:
            return {}

        return {
            "ips": set(re.findall(self.IP_PATTERN, text)),
            "domains": set(re.findall(self.DOMAIN_PATTERN, text.lower())),
            "urls": set(re.findall(self.URL_PATTERN, text)),
            "md5": set(re.findall(self.HASH_MD5, text)),
            "sha1": set(re.findall(self.HASH_SHA1, text)),
            "sha256": set(re.findall(self.HASH_SHA256, text)),
            "emails": set(re.findall(self.EMAIL_PATTERN, text)),
        }

    def classify_threat_type(
        self, ioc_value: str, ioc_type: str, context: str = ""
    ) -> str:
        """Classifies the threat type based on the IOC and its context."""
        context = context.lower()

        if "brute" in context or "login" in context:
            return "Brute Force Source"
        if "scanner" in context or "nmap" in context or "port scan" in context:
            return "Scanner IP"
        if "phishing" in context or "mail" in context:
            return "Phishing Source"
        if "c2" in context or "command and control" in context:
            return "Malware C2"

        # Default classifications
        if ioc_type == "ips":
            return "Suspicious IP"
        if ioc_type in ["md5", "sha1", "sha256"]:
            return "Malware Hash"
        if ioc_type == "domains":
            return "Suspicious Domain"
        return "Generic Threat"

    def calculate_confidence(
        self, honeypot_count: int, external_confirmed: bool = False
    ) -> str:
        """
        Calculates a confidence score for the IOC.
        - HIGH: Multiple honeypots or External confirmation.
        - MEDIUM: Single detection.
        """
        if external_confirmed or honeypot_count > 1:
            return "HIGH"
        return "MEDIUM"

    def process_event(
        self, event_data: Dict[str, Any], external_confirmed: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Processes a single event, extracts IOCs, and returns a list of enriched IOC objects.
        """
        raw_text = str(event_data.get("raw_data", ""))
        source_ip = event_data.get("source_ip", "")
        extracted = self.extract_from_text(raw_text)

        # Add source IP if it's not internal (simplified check for now)
        if source_ip and not source_ip.startswith(("10.", "192.168.", "172.16.")):
            extracted["ips"].add(source_ip)

        results = []
        # Simulate honeypot count for this event (could be more robust if tracking globally)
        honeypot_count = 1

        for ioc_type, values in extracted.items():
            for value in values:
                threat_type = self.classify_threat_type(value, ioc_type, raw_text)
                confidence = self.calculate_confidence(
                    honeypot_count, external_confirmed
                )

                results.append(
                    {
                        "value": value,
                        "type": ioc_type,
                        "threat_type": threat_type,
                        "confidence": confidence,
                        "first_seen": datetime.utcnow().isoformat(),
                        "context": raw_text[:200],  # Provide snippet
                    }
                )

        return results


# Singleton instance
ioc_extractor = IOCExtractor()
