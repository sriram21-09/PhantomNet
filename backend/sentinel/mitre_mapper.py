"""
backend/sentinel/mitre_mapper.py
---------------------------------
PhantomNet Sentinel Layer — MITRE ATT&CK Technique Mapper

Translates raw signature names (produced by ml/signatures.py SignatureEngine)
into structured MITRE ATT&CK technique objects.

Signature → ATT&CK mapping (Phase 5, Week 1, Day 2 — 12 total mappings):
  SSH_AUTH_FAILURE         → T1110.001  Brute Force: Password Guessing
  SSH_HIGH_ACTIVITY        → T1021.004  Remote Services: SSH
  HTTP_SQL_INJECTION       → T1190      Exploit Public-Facing Application
  HTTP_XSS_ATTEMPT         → T1059.007  Command and Scripting Interpreter: JavaScript
  HTTP_PATH_TRAVERSAL      → T1083      File and Directory Discovery
  HTTP_SCANNER_BEHAVIOR    → T1046      Network Service Discovery
  FTP_DATA_EXFILTRATION    → T1048.003  Exfiltration Over Unencrypted Non-C2 Protocol
  SMTP_LARGE_PAYLOAD       → T1071.003  Application Layer Protocol: Mail Protocols
  DISTRIBUTED_BRUTE_FORCE  → T1110.004  Brute Force: Credential Stuffing
  LOW_AND_SLOW_SCAN        → T1595.001  Active Scanning: Scanning IP Blocks
  MULTI_PROTOCOL_ATTACK    → T1046      Network Service Discovery
  HIGH_FREQUENCY_ATTACK    → T1498      Network Denial of Service

Public API
----------
  map_signature(signature_name: str) -> dict | None
      Maps a single signature name to an ATT&CK technique dict.
      Returns None if the signature is not in the mapping table.

  map_signatures(signature_names: list[str]) -> list[dict]
      Maps a list of signature names, skipping any unmapped ones.
      Returns deduplicated results by technique_id.

  get_all_techniques() -> list[dict]
      Returns the full mapping table as a list (for API/UI consumption).

  get_technique(signature_name: str) -> dict | None
      Returns a slim dict {id, name, tactic, mitre_url} for a signature,
      or None if the signature is not mapped.

  get_all_mappings() -> dict[str, dict]
      Returns a shallow copy of the full internal _TECHNIQUE_MAP dictionary.
      Keys are signature names; values are technique dicts (without 'signature'
      field populated).

ATT&CK Technique Object Schema (full)
--------------------------------------
  {
    "technique_id":   str   # e.g. "T1110.001"
    "technique_name": str   # e.g. "Brute Force: Password Guessing"
    "tactic":         str   # e.g. "Credential Access"
    "tactic_id":      str   # e.g. "TA0006"
    "description":    str   # Short human-readable description
    "url":            str   # Official ATT&CK reference URL
    "severity":       str   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    "signature":      str   # Source signature name that triggered this
  }

get_technique() Slim Schema
----------------------------
  {
    "id":        str   # technique_id, e.g. "T1110.001"
    "name":      str   # technique_name
    "tactic":    str   # tactic name
    "mitre_url": str   # Official ATT&CK reference URL
  }
"""

from __future__ import annotations
from typing import Optional

# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Lookup Table
# Key   : signature name (matches SignatureEngine output exactly)
# Value : ATT&CK technique dict (signature field populated by map_signature())
# ---------------------------------------------------------------------------
_TECHNIQUE_MAP: dict[str, dict] = {
    # ── SSH ─────────────────────────────────────────────────────────────────
    "SSH_AUTH_FAILURE": {
        "technique_id":   "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic":         "Credential Access",
        "tactic_id":      "TA0006",
        "description": (
            "Adversaries attempt to gain access to accounts by systematically "
            "guessing passwords. Repeated SSH authentication failures indicate "
            "an automated or manual password-guessing campaign targeting the "
            "honeypot service."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "severity": "HIGH",
    },
    "SSH_HIGH_ACTIVITY": {
        "technique_id":   "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic":         "Lateral Movement",
        "tactic_id":      "TA0008",
        "description": (
            "Adversaries use Secure Shell (SSH) to log into remote machines "
            "during lateral movement. Elevated SSH session activity above normal "
            "thresholds suggests an attacker may be actively exploring or "
            "pivoting through the network via the SSH honeypot."
        ),
        "url": "https://attack.mitre.org/techniques/T1021/004/",
        "severity": "MEDIUM",
    },

    # ── HTTP ─────────────────────────────────────────────────────────────────
    "HTTP_SQL_INJECTION": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "description": (
            "Adversaries exploit vulnerabilities in internet-facing applications "
            "to gain initial access. SQL injection payloads detected in HTTP "
            "requests (UNION, SELECT, DROP) indicate an attempt to manipulate "
            "the backend database and potentially extract sensitive data."
        ),
        "url": "https://attack.mitre.org/techniques/T1190/",
        "severity": "CRITICAL",
    },
    "HTTP_XSS_ATTEMPT": {
        "technique_id":   "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic":         "Execution",
        "tactic_id":      "TA0002",
        "description": (
            "Adversaries abuse JavaScript to execute malicious commands in a "
            "victim's browser context. Cross-site scripting (XSS) payloads "
            "detected in HTTP requests (<script>, onerror=) indicate an attempt "
            "to inject and execute client-side scripts against application users."
        ),
        "url": "https://attack.mitre.org/techniques/T1059/007/",
        "severity": "HIGH",
    },
    "HTTP_PATH_TRAVERSAL": {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic":         "Discovery",
        "tactic_id":      "TA0007",
        "description": (
            "Adversaries enumerate files and directories to understand the "
            "system layout and locate sensitive data. Path traversal sequences "
            "(../) detected in HTTP requests indicate an attempt to access "
            "files outside the web root, such as /etc/passwd or configuration "
            "files."
        ),
        "url": "https://attack.mitre.org/techniques/T1083/",
        "severity": "HIGH",
    },
    "HTTP_SCANNER_BEHAVIOR": {
        "technique_id":   "T1046",
        "technique_name": "Network Service Discovery",
        "tactic":         "Discovery",
        "tactic_id":      "TA0007",
        "description": (
            "Adversaries scan networks to discover accessible services and "
            "potential attack vectors. High URL request rates from a single "
            "source indicate automated scanner or web crawler behaviour probing "
            "the HTTP honeypot for vulnerable endpoints."
        ),
        "url": "https://attack.mitre.org/techniques/T1046/",
        "severity": "MEDIUM",
    },

    # ── FTP ──────────────────────────────────────────────────────────────────
    "FTP_DATA_EXFILTRATION": {
        "technique_id":   "T1048.003",
        "technique_name": "Exfiltration Over Unencrypted Non-C2 Protocol",
        "tactic":         "Exfiltration",
        "tactic_id":      "TA0010",
        "description": (
            "Adversaries exfiltrate data over unencrypted, non-command-and-control "
            "protocols to avoid detection and blend with normal network traffic. "
            "Large or anomalous FTP data transfers on port 20 indicate staged data "
            "being pushed to an attacker-controlled server over plain-text FTP."
        ),
        "url": "https://attack.mitre.org/techniques/T1048/003/",
        "severity": "CRITICAL",
    },

    # ── SMTP ─────────────────────────────────────────────────────────────────
    "SMTP_LARGE_PAYLOAD": {
        "technique_id":   "T1071.003",
        "technique_name": "Application Layer Protocol: Mail Protocols",
        "tactic":         "Command and Control",
        "tactic_id":      "TA0011",
        "description": (
            "Adversaries communicate with compromised systems using standard mail "
            "protocols (SMTP, POP3, IMAP) to blend C2 traffic with legitimate "
            "email activity. Oversized SMTP payloads on port 25 suggest data "
            "exfiltration or C2 channel establishment via email attachments."
        ),
        "url": "https://attack.mitre.org/techniques/T1071/003/",
        "severity": "HIGH",
    },

    # ── Distributed / Advanced Brute Force ───────────────────────────────────
    "DISTRIBUTED_BRUTE_FORCE": {
        "technique_id":   "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic":         "Credential Access",
        "tactic_id":      "TA0006",
        "description": (
            "Adversaries use large lists of username/password pairs obtained from "
            "prior data breaches to gain access to user accounts. Authentication "
            "attempts originating from multiple distinct source IPs in coordinated "
            "bursts indicate a distributed credential-stuffing campaign targeting "
            "the honeypot's authentication surface."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/004/",
        "severity": "CRITICAL",
    },

    # ── Reconnaissance / Scanning ────────────────────────────────────────────
    "LOW_AND_SLOW_SCAN": {
        "technique_id":   "T1595.001",
        "technique_name": "Active Scanning: Scanning IP Blocks",
        "tactic":         "Reconnaissance",
        "tactic_id":      "TA0043",
        "description": (
            "Adversaries scan IP address blocks to build a map of live hosts and "
            "accessible services before launching targeted attacks. Low-rate, "
            "time-distributed probes spread across many destination IPs are a "
            "classic evasion technique designed to fly below IDS rate-based "
            "thresholds while still performing systematic reconnaissance."
        ),
        "url": "https://attack.mitre.org/techniques/T1595/001/",
        "severity": "MEDIUM",
    },
    "MULTI_PROTOCOL_ATTACK": {
        "technique_id":   "T1046",
        "technique_name": "Network Service Discovery",
        "tactic":         "Discovery",
        "tactic_id":      "TA0007",
        "description": (
            "Adversaries enumerate network services across multiple protocols "
            "to identify open ports, running services, and potential attack "
            "vectors. Simultaneous probing across TCP, UDP, and ICMP from the "
            "same source indicates broad-spectrum service discovery activity "
            "targeting the entire honeypot service portfolio."
        ),
        "url": "https://attack.mitre.org/techniques/T1046/",
        "severity": "HIGH",
    },

    # ── Impact / Availability ────────────────────────────────────────────────
    "HIGH_FREQUENCY_ATTACK": {
        "technique_id":   "T1498",
        "technique_name": "Network Denial of Service",
        "tactic":         "Impact",
        "tactic_id":      "TA0040",
        "description": (
            "Adversaries perform network denial-of-service attacks to degrade or "
            "block availability of targeted resources. Extremely high packet or "
            "connection rates from one or more sources indicate a volumetric "
            "flood attack aimed at exhausting the honeypot's bandwidth or "
            "connection-table capacity, rendering the service unavailable."
        ),
        "url": "https://attack.mitre.org/techniques/T1498/",
        "severity": "CRITICAL",
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_signature(signature_name: str) -> Optional[dict]:
    """
    Map a single signature name to its MITRE ATT&CK technique.

    Args:
        signature_name: Exact string as returned by SignatureEngine.check_signatures()
                        e.g. "SSH_AUTH_FAILURE"

    Returns:
        A technique dict with a 'signature' field populated, or None if the
        signature is not in the mapping table.

    Example:
        >>> result = map_signature("SSH_AUTH_FAILURE")
        >>> result["technique_id"]
        'T1110.001'
    """
    template = _TECHNIQUE_MAP.get(signature_name)
    if template is None:
        return None
    # Return a copy so callers cannot mutate the master table
    technique = dict(template)
    technique["signature"] = signature_name
    return technique


def map_signatures(signature_names: list) -> list:
    """
    Map a list of signature names to ATT&CK techniques.

    Unmapped signatures are silently skipped.
    Deduplicates by technique_id so the same technique is not returned twice
    even if multiple signatures resolve to it.

    Args:
        signature_names: List of signature strings from SignatureEngine.

    Returns:
        List of technique dicts, one per unique technique_id found.

    Example:
        >>> sigs = ["SSH_AUTH_FAILURE", "UNKNOWN_SIG", "HTTP_SQL_INJECTION"]
        >>> results = map_signatures(sigs)
        >>> len(results)  # UNKNOWN_SIG is skipped
        2
    """
    seen_ids: set[str] = set()
    techniques: list[dict] = []

    for sig in signature_names:
        technique = map_signature(sig)
        if technique is None:
            continue
        tid = technique["technique_id"]
        if tid not in seen_ids:
            seen_ids.add(tid)
            techniques.append(technique)

    return techniques


def get_all_techniques() -> list:
    """
    Return the complete ATT&CK technique mapping table.

    Useful for API endpoints that expose the full technique catalogue
    or for seeding the Sentinel Dashboard's technique reference panel.

    Returns:
        List of all technique dicts with 'signature' populated.
    """
    return [
        {**template, "signature": sig}
        for sig, template in _TECHNIQUE_MAP.items()
    ]


def get_technique(signature_name: str) -> Optional[dict]:
    """
    Return a slim technique summary for a given signature name.

    This is a lightweight alternative to ``map_signature()`` intended for
    callers that only need the core identifiers — e.g. the Sentinel Dashboard
    badge renderer or the rule_generator reference field.

    Args:
        signature_name: Exact signature string (e.g. ``"SSH_AUTH_FAILURE"``).

    Returns:
        A dict with keys ``id``, ``name``, ``tactic``, and ``mitre_url``,
        or ``None`` if the signature is not present in the mapping table.

    Example:
        >>> t = get_technique("FTP_DATA_EXFILTRATION")
        >>> t["id"]
        'T1048.003'
        >>> t["tactic"]
        'Exfiltration'
    """
    template = _TECHNIQUE_MAP.get(signature_name)
    if template is None:
        return None
    return {
        "id":        template["technique_id"],
        "name":      template["technique_name"],
        "tactic":    template["tactic"],
        "mitre_url": template["url"],
    }


def get_all_mappings() -> dict:
    """
    Return a shallow copy of the complete internal signature → technique map.

    Unlike ``get_all_techniques()``, this preserves the original dict-of-dicts
    structure keyed by signature name, which is more convenient for callers
    that need O(1) lookup without iterating a list.

    Returns:
        A ``dict[str, dict]`` where each key is a signature name and each value
        is the technique dict (without the ``'signature'`` field added).

    Example:
        >>> mappings = get_all_mappings()
        >>> len(mappings)
        12
        >>> mappings["HIGH_FREQUENCY_ATTACK"]["technique_id"]
        'T1498'
    """
    # Return a shallow copy so callers cannot mutate the master table keys,
    # while inner dicts remain shared (consistent with map_signature behaviour).
    return dict(_TECHNIQUE_MAP)
