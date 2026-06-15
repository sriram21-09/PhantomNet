"""
backend/sentinel/mitre_mapper.py
---------------------------------
PhantomNet Sentinel Layer — MITRE ATT&CK Technique Mapper

Translates raw signature names (produced by ml/signatures.py SignatureEngine)
into structured MITRE ATT&CK technique objects.

Signature → ATT&CK mapping (Phase 5, Week 1, Day 2):
  SSH_AUTH_FAILURE    → T1110.001  Brute Force: Password Guessing
  SSH_HIGH_ACTIVITY   → T1021.004  Remote Services: SSH
  HTTP_SQL_INJECTION  → T1190      Exploit Public-Facing Application
  HTTP_XSS_ATTEMPT    → T1059.007  Command and Scripting: JavaScript
  HTTP_PATH_TRAVERSAL → T1083      File and Directory Discovery
  HTTP_SCANNER_BEHAVIOR→ T1046     Network Service Scanning

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

ATT&CK Technique Object Schema
-------------------------------
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
        "technique_name": "Network Service Scanning",
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
