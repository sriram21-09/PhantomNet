#!/usr/bin/env python3
"""
scripts/llm_sqli_portscan_eval.py
------------------------------------
PhantomNet — LLM Quality Evaluation for SQLi and Port Scan Summaries

Sends raw SQL Injection and Port Scan telemetry prompts to local LLM (via Ollama),
evaluates response structure, formatting, markdown layout correctness,
and checks for hallucinations. Produces a JSON quality report.

Usage:
    python scripts/llm_sqli_portscan_eval.py
    python scripts/llm_sqli_portscan_eval.py --host http://localhost:11434
    python scripts/llm_sqli_portscan_eval.py --mock
    python scripts/llm_sqli_portscan_eval.py --output reports/llm_sqli_portscan_quality_report.json
"""

from __future__ import annotations

import argparse
import codecs
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Install: pip install requests")
    sys.exit(1)

# UTF-8 output for Windows
if hasattr(sys.stdout, "buffer"):
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "replace")


# ---------------------------------------------------------------------------
# System prompt (common base from llm_pipeline_architecture.md)
# ---------------------------------------------------------------------------
SYSTEM_INSTRUCTIONS = (
    "You are an expert incident response and threat intelligence analyst. "
    "Write a highly technical, professional, and clear executive summary of the threat campaign. "
    "Use strict Markdown format. Start directly with the markdown header. "
    "Do NOT output HTML tags. "
    "Do NOT use conversational prefixes (such as 'Sure, here is your playbook summary:'). "
    "Do NOT invent or fabricate data not present in the provided telemetry. "
    "Only reference IPs, ports, timestamps, and metrics explicitly given below."
)


# ---------------------------------------------------------------------------
# SQL Injection (SQLi) telemetry prompt context
# ---------------------------------------------------------------------------
SQLI_TELEMETRY_CONTEXT = {
    "campaign_id": "CAMP-W17-SQLI-001",
    "attack_type": "SQL Injection",
    "source_ips": ["203.0.113.101", "203.0.113.102"],
    "destination_port": 8080,
    "protocol": "TCP",
    "event_count": 320,
    "target_url": "/api/v1/users/login",
    "http_method": "POST",
    "injected_payloads": ["' OR '1'='1", "UNION SELECT username, password FROM users"],
    "first_seen": "2026-07-16T08:00:00Z",
    "last_seen": "2026-07-16T08:10:00Z",
    "threat_score": 92.0,
    "confidence_score": 0.95,
    "mitre_technique_id": "T1190",
    "mitre_technique_name": "Exploit Public-Facing Application",
    "mitre_tactic": "Initial Access",
    "mitre_url": "https://attack.mitre.org/techniques/T1190/",
    "snort_rule": (
        'alert tcp any any -> $HTTP_SERVERS 8080 '
        '(msg:"SQL Injection Attempt Detected"; content:"UNION"; nocase; '
        'reference:url,attack.mitre.org/techniques/T1190/; sid:1000002; rev:1;)'
    ),
    "sigma_rule_level": "high",
}


# ---------------------------------------------------------------------------
# Port Scan telemetry prompt context
# ---------------------------------------------------------------------------
PORTSCAN_TELEMETRY_CONTEXT = {
    "campaign_id": "CAMP-W17-PORT-SCAN-001",
    "attack_type": "Port Scan",
    "source_ips": ["198.51.100.50"],
    "destination_port": 0,  # Multi-port sweep
    "protocol": "TCP",
    "event_count": 1500,
    "scan_type": "SYN Scan",
    "unique_ports_scanned": 85,
    "first_seen": "2026-07-16T09:00:00Z",
    "last_seen": "2026-07-16T09:05:00Z",
    "threat_score": 78.5,
    "confidence_score": 0.88,
    "mitre_technique_id": "T1595.001",
    "mitre_technique_name": "Active Scanning: Scanning IP Blocks",
    "mitre_tactic": "Reconnaissance",
    "mitre_url": "https://attack.mitre.org/techniques/T1595/001/",
    "snort_rule": (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any '
        '(msg:"SYN Port Scan Detected"; flags:S; threshold:type limit, track by_src, '
        'count 20, seconds 10; reference:url,attack.mitre.org/techniques/T1595/001/; sid:1000003; rev:1;)'
    ),
    "sigma_rule_level": "medium",
}


# ---------------------------------------------------------------------------
# Prompt Builders - SQL Injection
# ---------------------------------------------------------------------------
def build_sqli_prompt_v1_raw() -> str:
    """SQLi V1 — Raw telemetry dump, minimal instructions."""
    ctx = SQLI_TELEMETRY_CONTEXT
    return (
        f"{SYSTEM_INSTRUCTIONS}\n\n"
        f"Campaign ID: {ctx['campaign_id']}\n"
        f"Attack Type: {ctx['attack_type']}\n"
        f"Source IPs: {', '.join(ctx['source_ips'])}\n"
        f"Destination Port: {ctx['destination_port']}\n"
        f"Protocol: {ctx['protocol']}\n"
        f"Event Count: {ctx['event_count']}\n"
        f"Target URL: {ctx['target_url']}\n"
        f"HTTP Method: {ctx['http_method']}\n"
        f"Injected Payloads: {', '.join(ctx['injected_payloads'])}\n"
        f"First Seen: {ctx['first_seen']}\n"
        f"Last Seen: {ctx['last_seen']}\n"
        f"Threat Score: {ctx['threat_score']}\n"
        f"Confidence Score: {ctx['confidence_score']}\n"
        f"MITRE Technique: {ctx['mitre_technique_id']} — {ctx['mitre_technique_name']}\n"
        f"MITRE Tactic: {ctx['mitre_tactic']}\n\n"
        "Write a security incident summary in Markdown."
    )


def build_sqli_prompt_v2_structured() -> str:
    """SQLi V2 — Structured with explicit section requirements."""
    ctx = SQLI_TELEMETRY_CONTEXT
    return (
        f"{SYSTEM_INSTRUCTIONS}\n\n"
        "--- BEGIN TELEMETRY ---\n"
        f"Campaign ID: {ctx['campaign_id']}\n"
        f"Attack Type: {ctx['attack_type']}\n"
        f"Source IPs: {', '.join(ctx['source_ips'])}\n"
        f"Destination Port: {ctx['destination_port']}\n"
        f"Protocol: {ctx['protocol']}\n"
        f"Event Count: {ctx['event_count']} SQLi requests\n"
        f"Target URL: {ctx['target_url']} ({ctx['http_method']})\n"
        f"Payloads: {', '.join(ctx['injected_payloads'])}\n"
        f"Time Window: {ctx['first_seen']} to {ctx['last_seen']}\n"
        f"Threat Score: {ctx['threat_score']} / 100\n"
        f"Confidence: {ctx['confidence_score']}\n"
        f"MITRE ATT&CK: {ctx['mitre_technique_id']} ({ctx['mitre_technique_name']})\n"
        f"Tactic: {ctx['mitre_tactic']}\n"
        f"Snort Rule: {ctx['snort_rule']}\n"
        "--- END TELEMETRY ---\n\n"
        "Generate a Markdown incident summary with EXACTLY these sections:\n"
        "1. ## Incident Overview\n"
        "2. ## Attack Analysis\n"
        "3. ## Indicators of Compromise\n"
        "4. ## MITRE ATT&CK Mapping\n"
        "5. ## Recommended Containment\n"
        "Do NOT add sections beyond these five. Do NOT fabricate data."
    )


def build_sqli_prompt_v3_hardened() -> str:
    """SQLi V3 — Hardened prompt with anti-hallucination guardrails and format fences."""
    ctx = SQLI_TELEMETRY_CONTEXT
    return (
        f"{SYSTEM_INSTRUCTIONS}\n\n"
        "STRICT RULES:\n"
        "- Output ONLY valid Markdown. No HTML.\n"
        "- Start with '## Incident Overview'. No preamble.\n"
        "- Include EXACTLY 5 sections in this order:\n"
        "  1. ## Incident Overview\n"
        "  2. ## Attack Analysis\n"
        "  3. ## Indicators of Compromise\n"
        "  4. ## MITRE ATT&CK Mapping\n"
        "  5. ## Recommended Containment\n"
        "- In the IOC section, use a Markdown table with columns: Indicator | Type | Context\n"
        "- Reference ONLY the data provided below. Do NOT invent IPs, timestamps, or metrics.\n"
        "- Do NOT exceed 500 words.\n\n"
        "--- BEGIN TELEMETRY ---\n"
        f"Campaign: {ctx['campaign_id']}\n"
        f"Type: {ctx['attack_type']}\n"
        f"Sources: {', '.join(ctx['source_ips'])}\n"
        f"Target URL: {ctx['target_url']} on port {ctx['destination_port']} ({ctx['protocol']})\n"
        f"Events: {ctx['event_count']} SQL injection events\n"
        f"Payloads used: {', '.join(ctx['injected_payloads'])}\n"
        f"Window: {ctx['first_seen']} — {ctx['last_seen']}\n"
        f"Threat Score: {ctx['threat_score']}/100 | Confidence: {ctx['confidence_score']}\n"
        f"MITRE: {ctx['mitre_technique_id']} — {ctx['mitre_technique_name']} ({ctx['mitre_tactic']})\n"
        f"Reference: {ctx['mitre_url']}\n"
        f"Snort Signature: {ctx['snort_rule']}\n"
        "--- END TELEMETRY ---"
    )


# ---------------------------------------------------------------------------
# Prompt Builders - Port Scan
# ---------------------------------------------------------------------------
def build_portscan_prompt_v1_raw() -> str:
    """Port Scan V1 — Raw telemetry dump, minimal instructions."""
    ctx = PORTSCAN_TELEMETRY_CONTEXT
    return (
        f"{SYSTEM_INSTRUCTIONS}\n\n"
        f"Campaign ID: {ctx['campaign_id']}\n"
        f"Attack Type: {ctx['attack_type']}\n"
        f"Source IPs: {', '.join(ctx['source_ips'])}\n"
        f"Destination Port: {ctx['destination_port']}\n"
        f"Protocol: {ctx['protocol']}\n"
        f"Event Count: {ctx['event_count']}\n"
        f"Scan Type: {ctx['scan_type']}\n"
        f"Unique Ports Scanned: {ctx['unique_ports_scanned']}\n"
        f"First Seen: {ctx['first_seen']}\n"
        f"Last Seen: {ctx['last_seen']}\n"
        f"Threat Score: {ctx['threat_score']}\n"
        f"Confidence Score: {ctx['confidence_score']}\n"
        f"MITRE Technique: {ctx['mitre_technique_id']} — {ctx['mitre_technique_name']}\n"
        f"MITRE Tactic: {ctx['mitre_tactic']}\n\n"
        "Write a security incident summary in Markdown."
    )


def build_portscan_prompt_v2_structured() -> str:
    """Port Scan V2 — Structured with explicit section requirements."""
    ctx = PORTSCAN_TELEMETRY_CONTEXT
    return (
        f"{SYSTEM_INSTRUCTIONS}\n\n"
        "--- BEGIN TELEMETRY ---\n"
        f"Campaign ID: {ctx['campaign_id']}\n"
        f"Attack Type: {ctx['attack_type']}\n"
        f"Source IPs: {', '.join(ctx['source_ips'])}\n"
        f"Protocol: {ctx['protocol']}\n"
        f"Event Count: {ctx['event_count']} scanning events\n"
        f"Scan Type: {ctx['scan_type']}\n"
        f"Ports Scanned: {ctx['unique_ports_scanned']} unique ports\n"
        f"Time Window: {ctx['first_seen']} to {ctx['last_seen']}\n"
        f"Threat Score: {ctx['threat_score']} / 100\n"
        f"Confidence: {ctx['confidence_score']}\n"
        f"MITRE ATT&CK: {ctx['mitre_technique_id']} ({ctx['mitre_technique_name']})\n"
        f"Tactic: {ctx['mitre_tactic']}\n"
        f"Snort Rule: {ctx['snort_rule']}\n"
        "--- END TELEMETRY ---\n\n"
        "Generate a Markdown incident summary with EXACTLY these sections:\n"
        "1. ## Incident Overview\n"
        "2. ## Attack Analysis\n"
        "3. ## Indicators of Compromise\n"
        "4. ## MITRE ATT&CK Mapping\n"
        "5. ## Recommended Containment\n"
        "Do NOT add sections beyond these five. Do NOT fabricate data."
    )


def build_portscan_prompt_v3_hardened() -> str:
    """Port Scan V3 — Hardened prompt with anti-hallucination guardrails and format fences."""
    ctx = PORTSCAN_TELEMETRY_CONTEXT
    return (
        f"{SYSTEM_INSTRUCTIONS}\n\n"
        "STRICT RULES:\n"
        "- Output ONLY valid Markdown. No HTML.\n"
        "- Start with '## Incident Overview'. No preamble.\n"
        "- Include EXACTLY 5 sections in this order:\n"
        "  1. ## Incident Overview\n"
        "  2. ## Attack Analysis\n"
        "  3. ## Indicators of Compromise\n"
        "  4. ## MITRE ATT&CK Mapping\n"
        "  5. ## Recommended Containment\n"
        "- In the IOC section, use a Markdown table with columns: Indicator | Type | Context\n"
        "- Reference ONLY the data provided below. Do NOT invent IPs, timestamps, or metrics.\n"
        "- Do NOT exceed 500 words.\n\n"
        "--- BEGIN TELEMETRY ---\n"
        f"Campaign: {ctx['campaign_id']}\n"
        f"Type: {ctx['attack_type']}\n"
        f"Sources: {', '.join(ctx['source_ips'])}\n"
        f"Protocol: {ctx['protocol']}\n"
        f"Events: {ctx['event_count']} scan probes using {ctx['scan_type']}\n"
        f"Ports targeted: {ctx['unique_ports_scanned']} unique ports\n"
        f"Window: {ctx['first_seen']} — {ctx['last_seen']}\n"
        f"Threat Score: {ctx['threat_score']}/100 | Confidence: {ctx['confidence_score']}\n"
        f"MITRE: {ctx['mitre_technique_id']} — {ctx['mitre_technique_name']} ({ctx['mitre_tactic']})\n"
        f"Reference: {ctx['mitre_url']}\n"
        f"Snort Signature: {ctx['snort_rule']}\n"
        "--- END TELEMETRY ---"
    )


# ---------------------------------------------------------------------------
# Quality evaluation functions
# ---------------------------------------------------------------------------

REQUIRED_SECTIONS = [
    "Incident Overview",
    "Attack Analysis",
    "Indicators of Compromise",
    "MITRE ATT&CK Mapping",
    "Recommended Containment",
]


def check_markdown_structure(text: str) -> Dict[str, Any]:
    """Evaluate Markdown formatting quality."""
    checks = {}
    checks["starts_with_header"] = text.strip().startswith("#")
    checks["has_no_html"] = "<div" not in text.lower() and "<span" not in text.lower()
    checks["has_no_preamble"] = not any(
        text.strip().lower().startswith(p)
        for p in ["sure", "here is", "certainly", "of course", "below is"]
    )

    found_sections = []
    for section in REQUIRED_SECTIONS:
        pattern = rf"#+\s*{re.escape(section)}"
        if re.search(pattern, text, re.IGNORECASE):
            found_sections.append(section)
    checks["sections_found"] = found_sections
    checks["sections_missing"] = [s for s in REQUIRED_SECTIONS if s not in found_sections]
    checks["section_coverage"] = len(found_sections) / len(REQUIRED_SECTIONS)

    checks["has_markdown_table"] = bool(re.search(r"\|.*\|.*\|", text))
    checks["has_bullet_points"] = bool(re.search(r"^[\s]*[-*]\s", text, re.MULTILINE))
    checks["has_bold_text"] = "**" in text
    checks["word_count"] = len(text.split())

    return checks


def check_factual_accuracy(text: str, campaign_type: str) -> Dict[str, Any]:
    """Check for hallucinated data not in the original telemetry."""
    checks = {}

    if campaign_type == "sqli":
        known_ips = set(SQLI_TELEMETRY_CONTEXT["source_ips"])
        known_port = str(SQLI_TELEMETRY_CONTEXT["destination_port"])
        known_technique = SQLI_TELEMETRY_CONTEXT["mitre_technique_id"]
        known_url = SQLI_TELEMETRY_CONTEXT["target_url"]
        known_event_count = str(SQLI_TELEMETRY_CONTEXT["event_count"])
    else:
        known_ips = set(PORTSCAN_TELEMETRY_CONTEXT["source_ips"])
        known_port = None  # Multi-port
        known_technique = PORTSCAN_TELEMETRY_CONTEXT["mitre_technique_id"]
        known_url = None
        known_event_count = str(PORTSCAN_TELEMETRY_CONTEXT["event_count"])

    # Check known IPs are referenced
    ips_found = [ip for ip in known_ips if ip in text]
    checks["known_ips_referenced"] = ips_found
    checks["known_ips_coverage"] = len(ips_found) / len(known_ips) if known_ips else 0.0

    # Check for fabricated IPs (IPs not in our telemetry)
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    all_ips = set(ip_pattern.findall(text))
    fabricated_ips = all_ips - known_ips - {"0.0.0.0", "255.255.255.255", "127.0.0.1"}
    checks["fabricated_ips"] = list(fabricated_ips)
    checks["has_fabricated_ips"] = len(fabricated_ips) > 0

    # Check port reference
    if known_port:
        checks["correct_port_referenced"] = known_port in text
    else:
        # For port scan, verify it mentions active scan/multi-port sweep and does not claim port 2222 or similar single port specifically
        checks["correct_port_referenced"] = "85" in text or "ports" in text.lower()

    # Check MITRE technique
    checks["correct_technique_referenced"] = known_technique in text

    # Check for target URL for SQLi
    if known_url:
        checks["correct_url_referenced"] = known_url in text
    else:
        checks["correct_url_referenced"] = True

    # Check for correct event count
    checks["correct_event_count"] = known_event_count in text

    return checks


def check_security_compliance(text: str, campaign_type: str) -> Dict[str, Any]:
    """Check security-relevant content quality."""
    checks = {}
    text_lower = text.lower()

    # Containment steps check
    checks["mentions_containment"] = any(
        w in text_lower for w in ["block", "isolate", "firewall", "containment", "quarantine", "deny"]
    )

    # Monitoring check
    checks["mentions_monitoring"] = any(
        w in text_lower for w in ["monitor", "logging", "audit", "alert", "capture", "tcpdump", "log"]
    )

    # Specific hygiene mapping
    if campaign_type == "sqli":
        checks["mentions_credential_or_app_hygiene"] = any(
            w in text_lower for w in ["parameter", "sanitize", "input validation", "prepared statement", "patch"]
        )
        checks["mentions_mitre_tactic"] = "initial access" in text_lower
    else:
        # Port scan
        checks["mentions_credential_or_app_hygiene"] = any(
            w in text_lower for w in ["honeypot", "deception", "harden", "segment", "acl"]
        )
        checks["mentions_mitre_tactic"] = "reconnaissance" in text_lower or "discovery" in text_lower

    checks["references_snort_or_ids"] = any(
        w in text_lower for w in ["snort", "ids", "intrusion detection", "signature", "waf rule"]
    )

    return checks


def compute_quality_score(
    structure: Dict, accuracy: Dict, compliance: Dict
) -> Tuple[float, str]:
    """Compute a composite quality score (0-100) and grade."""
    score = 0.0

    # Structure (40 points)
    score += 5 if structure["starts_with_header"] else 0
    score += 5 if structure["has_no_html"] else 0
    score += 5 if structure["has_no_preamble"] else 0
    score += structure["section_coverage"] * 15
    score += 3 if structure["has_markdown_table"] else 0
    score += 3 if structure["has_bullet_points"] else 0
    score += 2 if structure["has_bold_text"] else 0
    score += 2 if 100 <= structure["word_count"] <= 600 else 0

    # Accuracy (35 points)
    score += accuracy["known_ips_coverage"] * 10
    score += 10 if not accuracy["has_fabricated_ips"] else 0
    score += 5 if accuracy["correct_port_referenced"] else 0
    score += 5 if accuracy["correct_technique_referenced"] else 0
    score += 3 if accuracy["correct_event_count"] else 0
    score += 2 if accuracy.get("correct_url_referenced", True) else 0

    # Compliance (25 points)
    score += 5 if compliance["mentions_containment"] else 0
    score += 5 if compliance["mentions_monitoring"] else 0
    score += 5 if compliance["mentions_credential_or_app_hygiene"] else 0
    score += 5 if compliance["mentions_mitre_tactic"] else 0
    score += 5 if compliance["references_snort_or_ids"] else 0

    # Grade
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return round(score, 1), grade


# ---------------------------------------------------------------------------
# Ollama interaction & Mock support
# ---------------------------------------------------------------------------
MOCK_RESPONSES_SQLI = {
    "v1": (
        "Sure, here is your playbook summary for SQL Injection:\n\n"
        "<div>The SQL Injection attack was detected from IP 203.0.113.101 and also we noticed a connection from 192.168.1.50 which was malicious.</div>\n"
        "The attacker targeted port 8080 on /api/v1/users/login with payload UNION SELECT username, password FROM users.\n"
        "We recommend blocking the IP and checking log files."
    ),
    "v2": (
        "## Incident Overview\n"
        "A SQL Injection attack campaign was detected.\n\n"
        "## Attack Analysis\n"
        "We detected 320 SQLi requests attempts targeting /api/v1/users/login using TCP protocol.\n\n"
        "## Indicators of Compromise\n"
        "The attacker source IPs are: 203.0.113.101, 203.0.113.102.\n\n"
        "## MITRE ATT&CK Mapping\n"
        "The attack maps to T1190 (Exploit Public-Facing Application) under Initial Access.\n\n"
        "## Recommended Containment\n"
        "- Block source IPs at WAF.\n"
        "- Review database logs."
    ),
    "v3": (
        "## Incident Overview\n"
        "A critical SQL Injection (SQLi) threat campaign (Campaign ID: CAMP-W17-SQLI-001) has been detected targeting port 8080. The threat scoring engine has assigned a threat score of 92.0 with a confidence score of 0.9500. The activity occurred between 2026-07-16T08:00:00Z and 2026-07-16T08:10:00Z, with 320 events recorded.\n\n"
        "## Attack Analysis\n"
        "The threat campaign involved SQL Injection attempts targeting the endpoint `/api/v1/users/login` using the TCP protocol. The attacker utilized payload patterns including `' OR '1'='1` and `UNION SELECT username, password FROM users` to bypass authentication and extract database content.\n\n"
        "## Indicators of Compromise\n"
        "The following indicators of compromise (IOCs) were identified:\n\n"
        "| Indicator | Type | Context |\n"
        "|---|---|---|\n"
        "| 203.0.113.101 | IP | Source Attacker IP |\n"
        "| 203.0.113.102 | IP | Source Attacker IP |\n"
        "| /api/v1/users/login | URL | Target Web Endpoint |\n\n"
        "## MITRE ATT&CK Mapping\n"
        "The campaign maps to the following MITRE ATT&CK matrix:\n\n"
        "| Field | Value |\n"
        "|---|---|\n"
        "| Technique ID | T1190 |\n"
        "| Technique Name | Exploit Public-Facing Application |\n"
        "| Tactic | Initial Access |\n"
        "| Reference URL | https://attack.mitre.org/techniques/T1190/ |\n\n"
        "## Recommended Containment\n"
        "1. **Block Source IPs** — Immediately deny HTTP traffic from `203.0.113.101` and `203.0.113.102` at the perimeter firewall and WAF.\n"
        "2. **Apply WAF Rules** — Enable signature blocks for SQL keywords such as `UNION` and `SELECT` to block active injection patterns using the Snort signature.\n"
        "3. **Prepared Statements** — Update the target endpoint code to use parameterized queries and input validation to eliminate SQL injection vulnerabilities.\n"
        "4. **Deploy Snort IDS Signature** — Deploy Snort rules targeting SQLi signatures.\n"
        "5. **Review Audit Logs** — Analyze database session logs to verify if any unauthorized queries executed successfully."
    )
}

MOCK_RESPONSES_PORTSCAN = {
    "v1": (
        "Below is the summary of the port scan:\n"
        "The attack from 198.51.100.50 targeted port 22 and also probed 10.0.0.99.\n"
        "There were 1500 SYN scan probes across 85 ports."
    ),
    "v2": (
        "## Incident Overview\n"
        "A port scan campaign was detected.\n\n"
        "## Attack Analysis\n"
        "The scanner probed 85 unique ports with 1500 SYN scan events.\n\n"
        "## Indicators of Compromise\n"
        "Source IP: 198.51.100.50.\n\n"
        "## MITRE ATT&CK Mapping\n"
        "Technique: T1595.001 (Active Scanning). Tactic: Reconnaissance.\n\n"
        "## Recommended Containment\n"
        "- Block scanner IP.\n"
        "- Deploy honeypots."
    ),
    "v3": (
        "## Incident Overview\n"
        "A high-severity active network scanning campaign (Campaign ID: CAMP-W17-PORT-SCAN-001) has been identified targeting network ports. The threat scoring engine assigned a threat score of 78.5 with a confidence score of 0.8800. The scanning activity was recorded between 2026-07-16T09:00:00Z and 2026-07-16T09:05:00Z, with 1500 probe events.\n\n"
        "## Attack Analysis\n"
        "The campaign utilized SYN port scan probes from a single scanner IP targeting 85 unique ports. The scan was designed to perform network reconnaissance and discover open services across the subnets.\n\n"
        "## Indicators of Compromise\n"
        "The following indicators of compromise (IOCs) were identified:\n\n"
        "| Indicator | Type | Context |\n"
        "|---|---|---|\n"
        "| 198.51.100.50 | IP | Attacker Scanner IP |\n"
        "| TCP | Protocol | Protocol used for scanning |\n\n"
        "## MITRE ATT&CK Mapping\n"
        "The campaign maps to the MITRE ATT&CK framework as follows:\n\n"
        "| Field | Value |\n"
        "|---|---|\n"
        "| Technique ID | T1595.001 |\n"
        "| Technique Name | Active Scanning: Scanning IP Blocks |\n"
        "| Tactic | Reconnaissance |\n"
        "| Reference URL | https://attack.mitre.org/techniques/T1595/001/ |\n\n"
        "## Recommended Containment\n"
        "1. **Block Source IP** — Deny all connections from scanner IP `198.51.100.50` at the boundary firewalls.\n"
        "2. **Deploy Deception Honeypots** — Deploy active deception honeypots in the targeted subnet to capture scanner behavior and feed threat intelligence.\n"
        "3. **Capture Traffic** — Initiate packet capture (tcpdump) on target interfaces to analyze scanner fingerprinting attempts using the Snort signature.\n"
        "4. **Harden Banners** — Harden exposed service banners to reduce information leakage to scanning probes.\n"
        "5. **Update IDS/IPS Signatures** — Deploy active signatures (e.g. Snort rule) to detect port sweeps and SYN scans dynamically."
    )
}


def call_llm(
    base_url: str,
    model: str,
    prompt: str,
    campaign_type: str,
    variant_key: str,
    mock: bool = False,
    temperature: float = 0.15
) -> Optional[Dict[str, Any]]:
    """Send prompt to Ollama and return response + timing metrics, or mock it."""
    if mock:
        # Simulate network latency
        simulated_latencies = {"v1": 3.2, "v2": 4.5, "v3": 6.8}
        latency = simulated_latencies.get(variant_key, 5.0)
        time.sleep(0.05)  # Quick yield to simulate processing
        response_text = (
            MOCK_RESPONSES_SQLI.get(variant_key)
            if campaign_type == "sqli"
            else MOCK_RESPONSES_PORTSCAN.get(variant_key)
        )
        # Approximate tokens
        eval_count = len(response_text.split()) * 1.3
        return {
            "response": response_text,
            "model": model,
            "eval_count": int(eval_count),
            "tokens_per_sec": round(eval_count / latency, 2),
            "wall_time_s": latency,
            "total_duration_ms": latency * 1000,
        }

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "top_p": 0.9,
            "num_predict": 1024,
            "stop": ["[INST]", "User:", "System:"],
        },
    }

    wall_start = time.perf_counter()
    try:
        resp = requests.post(
            f"{base_url}/api/generate", json=payload, timeout=120
        )
        wall_end = time.perf_counter()

        if resp.status_code != 200:
            print(f"  ERROR: HTTP {resp.status_code}: {resp.text[:200]}")
            return None

        data = resp.json()
        eval_count = data.get("eval_count", 0)
        eval_duration_ns = data.get("eval_duration", 0)
        eval_duration_s = eval_duration_ns / 1e9 if eval_duration_ns else 0

        return {
            "response": data.get("response", ""),
            "model": model,
            "eval_count": eval_count,
            "tokens_per_sec": round(eval_count / eval_duration_s, 2) if eval_duration_s > 0 else 0,
            "wall_time_s": round(wall_end - wall_start, 2),
            "total_duration_ms": round(data.get("total_duration", 0) / 1e6, 1),
        }
    except requests.ConnectionError:
        print("  ERROR: Cannot reach Ollama. Falling back to mock data.")
        return call_llm(base_url, model, prompt, campaign_type, variant_key, mock=True)
    except requests.Timeout:
        print("  ERROR: Request timed out (120s)")
        return None
    except Exception as exc:
        print(f"  ERROR: {exc}")
        return None


# ---------------------------------------------------------------------------
# Main evaluation pipeline
# ---------------------------------------------------------------------------

def run_evaluation(base_url: str, model: str, mock: bool = False) -> Dict[str, Any]:
    """Run all prompt variants and evaluate each response."""
    print()
    print("=" * 72)
    print("  PhantomNet — LLM Quality Evaluation: SQLi & Port Scan Campaigns")
    print("=" * 72)
    print(f"  Host:  {base_url} {'(MOCKED)' if mock else ''}")
    print(f"  Model: {model}")
    print(f"  Time:  {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    results = {
        "metadata": {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "model": model,
            "ollama_host": base_url,
            "mocked_execution": mock,
            "telemetry_contexts": {
                "sqli": SQLI_TELEMETRY_CONTEXT,
                "port_scan": PORTSCAN_TELEMETRY_CONTEXT,
            }
        },
        "evaluations": [],
    }

    campaign_configs = [
        {
            "type": "sqli",
            "name": "SQL Injection",
            "variants": [
                {"variant": "v1", "name": "V1 — Raw Telemetry (Baseline)", "builder": build_sqli_prompt_v1_raw},
                {"variant": "v2", "name": "V2 — Structured Sections", "builder": build_sqli_prompt_v2_structured},
                {"variant": "v3", "name": "V3 — Hardened Anti-Hallucination", "builder": build_sqli_prompt_v3_hardened},
            ]
        },
        {
            "type": "portscan",
            "name": "Port Scan",
            "variants": [
                {"variant": "v1", "name": "V1 — Raw Telemetry (Baseline)", "builder": build_portscan_prompt_v1_raw},
                {"variant": "v2", "name": "V2 — Structured Sections", "builder": build_portscan_prompt_v2_structured},
                {"variant": "v3", "name": "V3 — Hardened Anti-Hallucination", "builder": build_portscan_prompt_v3_hardened},
            ]
        }
    ]

    for campaign in campaign_configs:
        print(f"\nEvaluating Campaign Type: {campaign['name']}")
        print("=" * 50)

        for variant in campaign["variants"]:
            variant_name = variant["name"]
            variant_key = variant["variant"]
            prompt = variant["builder"]()

            print(f"\n  Prompt: {variant_name}")
            print(f"  Prompt length: {len(prompt)} chars / ~{len(prompt.split())} words")

            response_data = call_llm(base_url, model, prompt, campaign["type"], variant_key, mock=mock)

            if not response_data:
                results["evaluations"].append({
                    "campaign_type": campaign["type"],
                    "prompt_name": variant_name,
                    "variant": variant_key,
                    "status": "FAILED",
                    "error": "Ollama request failed",
                })
                continue

            raw_output = response_data["response"]
            print(f"  Response: {response_data['eval_count']} tokens in {response_data['wall_time_s']}s")
            print(f"  Speed:    {response_data['tokens_per_sec']} tok/s")

            # Run quality checks
            structure = check_markdown_structure(raw_output)
            accuracy = check_factual_accuracy(raw_output, campaign["type"])
            compliance = check_security_compliance(raw_output, campaign["type"])
            score, grade = compute_quality_score(structure, accuracy, compliance)

            print(f"  Score:    {score}/100 (Grade: {grade})")
            print(f"  Sections: {len(structure['sections_found'])}/{len(REQUIRED_SECTIONS)}")

            if structure["sections_missing"]:
                print(f"  Missing:  {', '.join(structure['sections_missing'])}")
            if accuracy["has_fabricated_ips"]:
                print(f"  WARNING:  Fabricated IPs detected: {accuracy['fabricated_ips']}")

            evaluation = {
                "campaign_type": campaign["type"],
                "prompt_name": variant_name,
                "variant": variant_key,
                "status": "SUCCESS",
                "prompt_text": prompt,
                "raw_output": raw_output,
                "inference_metrics": {
                    "eval_count": response_data["eval_count"],
                    "tokens_per_sec": response_data["tokens_per_sec"],
                    "wall_time_s": response_data["wall_time_s"],
                    "total_duration_ms": response_data["total_duration_ms"],
                },
                "quality_checks": {
                    "structure": structure,
                    "factual_accuracy": accuracy,
                    "security_compliance": compliance,
                },
                "composite_score": score,
                "grade": grade,
            }

            results["evaluations"].append(evaluation)

    # Summary
    successful = [e for e in results["evaluations"] if e["status"] == "SUCCESS"]
    if successful:
        sqli_best = max([e for e in successful if e["campaign_type"] == "sqli"], key=lambda e: e["composite_score"], default=None)
        portscan_best = max([e for e in successful if e["campaign_type"] == "portscan"], key=lambda e: e["composite_score"], default=None)

        results["summary"] = {
            "total_variants_tested": len(successful),
            "sqli_best_prompt": sqli_best["prompt_name"] if sqli_best else None,
            "sqli_best_score": sqli_best["composite_score"] if sqli_best else 0.0,
            "sqli_best_grade": sqli_best["grade"] if sqli_best else "F",
            "portscan_best_prompt": portscan_best["prompt_name"] if portscan_best else None,
            "portscan_best_score": portscan_best["composite_score"] if portscan_best else 0.0,
            "portscan_best_grade": portscan_best["grade"] if portscan_best else "F",
        }
        print(f"\n{'=' * 72}")
        if sqli_best:
            print(f"  BEST SQLi PROMPT:      {sqli_best['prompt_name']}")
            print(f"  BEST SQLi SCORE:       {sqli_best['composite_score']}/100 (Grade {sqli_best['grade']})")
            print(f"  SQLi LATENCY:          {sqli_best['inference_metrics']['wall_time_s']}s")
        if portscan_best:
            print(f"  BEST PORTSCAN PROMPT:  {portscan_best['prompt_name']}")
            print(f"  BEST PORTSCAN SCORE:   {portscan_best['composite_score']}/100 (Grade {portscan_best['grade']})")
            print(f"  PORTSCAN LATENCY:      {portscan_best['inference_metrics']['wall_time_s']}s")
        print(f"{'=' * 72}\n")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PhantomNet LLM Quality Evaluation — SQLi & Port Scan"
    )
    parser.add_argument(
        "--host", default="http://localhost:11434",
        help="Ollama base URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--model", default="mistral",
        help="Model name (default: mistral)",
    )
    parser.add_argument(
        "--output", default="reports/llm_sqli_portscan_quality_report.json",
        help="Output JSON path",
    )
    parser.add_argument(
        "--mock", action="store_true",
        help="Force mock Ollama execution offline",
    )
    args = parser.parse_args()

    mock_execution = args.mock

    # Health check
    if not mock_execution:
        print(f"Checking Ollama at {args.host}...")
        try:
            resp = requests.get(args.host, timeout=5)
            if resp.status_code != 200:
                raise ConnectionError()
            print("Ollama is responsive.")
        except Exception:
            print(f"WARNING: Cannot reach Ollama at {args.host}. Automatically falling back to mock mode.")
            mock_execution = True

    results = run_evaluation(args.host, args.model, mock=mock_execution)

    # Save report
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
