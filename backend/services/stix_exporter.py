import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from stix2 import (
    Bundle, Indicator, Identity, Relationship, 
    MarkingDefinition, TLP_WHITE, ExternalReference,
    ObservedData, ThreatActor, AttackPattern
)

# Setup Logger
logger = logging.getLogger("stix_exporter")
logger.setLevel(logging.INFO)

class STIXExporter:
    """
    Service for converting IOCs into STIX 2.1 JSON bundles.
    Supports Indicator, Identity, ObservedData, ThreatActor, AttackPattern, and Relationship objects.
    """

    def __init__(self, author_name: str = "PhantomNet AI", author_identity_id: Optional[str] = None):
        # Create or use the author identity
        if author_identity_id:
            self.author = author_identity_id
            self.identity = None
        else:
            self.identity = Identity(
                name=author_name,
                identity_class="organization",
                description="Automated Honeypot & Deception Platform"
            )
            self.author = self.identity.id

    def _get_stix_pattern(self, ioc_type: str, ioc_value: str) -> str:
        """Generates STIX 2.1 pattern based on IOC type."""
        patterns = {
            "ips": f"[ipv4-addr:value = '{ioc_value}']",
            "ipv6": f"[ipv6-addr:value = '{ioc_value}']",
            "domains": f"[domain-name:value = '{ioc_value}']",
            "urls": f"[url:value = '{ioc_value}']",
            "md5": f"[file:hashes.MD5 = '{ioc_value}']",
            "sha1": f"[file:hashes.SHA-1 = '{ioc_value}']",
            "sha256": f"[file:hashes.SHA-256 = '{ioc_value}']",
            "emails": f"[email-addr:value = '{ioc_value}']"
        }
        return patterns.get(ioc_type, f"[file:name = '{ioc_value}']")

    def create_threat_actor(self) -> ThreatActor:
        """Creates a generic Threat Actor object for attribution."""
        return ThreatActor(
            name="Unknown Adversary",
            description="Automated scanning or targeted attack detected by PhantomNet.",
            threat_actor_types=["scanner", "adversary"]
        )

    def create_attack_pattern(self, threat_type: str) -> AttackPattern:
        """Maps threat types to MITRE ATT&CK patterns."""
        name = "Gather Victim Network Information"
        description = "Adversary gathering IP addresses or scanning ports."
        
        if "Brute Force" in threat_type:
            name = "Brute Force"
            description = "Adversary attempting to gain access by guessing credentials."
        elif "Malware" in threat_type:
            name = "Malware Command and Control"
            description = "Adversary communicating with compromised systems."

        return AttackPattern(
            name=name,
            description=description,
            external_references=[
                ExternalReference(source_name="capec", external_id="CAPEC-112")
            ]
        )

    def generate_bundle(self, iocs: List[Dict[str, Any]]) -> str:
        """
        Generates a full STIX 2.1 Bundle JSON string from a list of IOCs.
        Includes Indicators, Observed Data, Threat Actor, and Attack Patterns.
        """
        if not iocs:
            return ""

        objects = []
        if self.identity:
            objects.append(self.identity)
            
        actor = self.create_threat_actor()
        objects.append(actor)

        for ioc in iocs:
            # 1. Indicator
            indicator = Indicator(
                name=ioc["threat_type"],
                description=f"Detected via PhantomNet Honeypots. Context: {ioc.get('context', 'N/A')}",
                pattern=self._get_stix_pattern(ioc["type"], ioc["value"]),
                pattern_type="stix",
                valid_from=datetime.now(),
                labels=[ioc["type"], ioc["threat_type"]],
                created_by_ref=self.author,
                confidence=80 if ioc["confidence"] == "HIGH" else 50,
                object_marking_refs=[TLP_WHITE.id]
            )
            objects.append(indicator)

            # 2. Observed Data
            observed = ObservedData(
                first_observed=datetime.now(),
                last_observed=datetime.now(),
                number_observed=1,
                objects={
                    "0": {"type": "ipv4-addr", "value": ioc["value"]} if ioc["type"] == "ips" else {"type": "domain-name", "value": ioc["value"]}
                }
            )
            objects.append(observed)

            # 3. Attack Pattern
            pattern = self.create_attack_pattern(ioc["threat_type"])
            objects.append(pattern)

            # 4. Relationships
            objects.append(Relationship(indicator, "indicates", pattern))
            objects.append(Relationship(actor, "uses", pattern))

        bundle = Bundle(objects=objects)
        return bundle.serialize(pretty=True)

# Singleton instance
stix_exporter = STIXExporter()
