#!/usr/bin/env python3
"""
scripts/llm_ssh_brute_force_eval.py
------------------------------------
PhantomNet — LLM Quality Evaluation for SSH Brute Force Summaries

Sends raw SSH brute force telemetry prompts to local Mistral (via Ollama),
evaluates response structure, formatting, markdown layout correctness,
and checks for hallucinations. Produces a JSON quality report.

Usage:
    python scripts/llm_ssh_brute_force_eval.py
    python scripts/llm_ssh_brute_force_eval.py --host http://localhost:11434
    python scripts/llm_ssh_brute_force_eval.py --output reports/llm_quality_report.json
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
# SSH Brute Force telemetry prompts — v1 (raw), v2 (refined), v3 (hardened)
# ---------------------------------------------------------------------------
SSH_TELEMETRY_CONTEXT = {
    "campaign_id": "CAMP-W17-SSH-BF-001",
    "attack_type": "SSH Brute Force",
    "source_ips": ["203.0.113.45", "203.0.113.46", "198.51.100.77"],
    "destination_port": 2222,
    "protocol": "TCP",
    "event_count": 450,
    "unique_usernames": 120,
    "first_seen": "2026-07-15T06:00:00Z",
    "last_seen": "2026-07-15T06:15:00Z",
    "threat_score": 87.5,
    "confidence_score": 0.92,
    "mitre_technique_id": "T1110.001",
    "mitre_technique_name": "Brute Force: Password Guessing",
    "mitre_tactic": "Credential Access",
    "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
    "snort_rule": (
        'alert tcp 203.0.113.45 any -> $HOME_NET 2222 '
        '(msg:"Campaign CAMP-W17-SSH-BF-001 SSH Brute Force from 203.0.113.45"; '
        'flow:to_server,established; threshold:type limit, track by_src, '
        'count 5, seconds 60; classtype:attempted-admin; '
        'reference:url,attack.mitre.org/techniques/T1110/001/; sid:1000001; rev:1;)'
    ),
    "sigma_rule_level": "high",
    "targeted_usernames": ["root", "admin", "ubuntu", "test", "user", "deploy"],
}


def build_prompt_v1_raw() -> str:
    """V1 — Raw telemetry dump, minimal instructions."""
    ctx = SSH_TELEMETRY_CONTEXT
    return (
        f"{SYSTEM_INSTRUCTIONS}\n\n"
        f"Campaign ID: {ctx['campaign_id']}\n"
        f"Attack Type: {ctx['attack_type']}\n"
        f"Source IPs: {', '.join(ctx['source_ips'])}\n"
        f"Destination Port: {ctx['destination_port']}\n"
        f"Protocol: {ctx['protocol']}\n"
        f"Event Count: {ctx['event_count']}\n"
        f"Unique Usernames Attempted: {ctx['unique_usernames']}\n"
        f"First Seen: {ctx['first_seen']}\n"
        f"Last Seen: {ctx['last_seen']}\n"
        f"Threat Score: {ctx['threat_score']}\n"
        f"Confidence Score: {ctx['confidence_score']}\n"
        f"MITRE Technique: {ctx['mitre_technique_id']} — {ctx['mitre_technique_name']}\n"
        f"MITRE Tactic: {ctx['mitre_tactic']}\n"
        f"Targeted Usernames: {', '.join(ctx['targeted_usernames'])}\n\n"
        "Write a security incident summary in Markdown."
    )


def build_prompt_v2_structured() -> str:
    """V2 — Structured with explicit section requirements."""
    ctx = SSH_TELEMETRY_CONTEXT
    return (
        f"{SYSTEM_INSTRUCTIONS}\n\n"
        "--- BEGIN TELEMETRY ---\n"
        f"Campaign ID: {ctx['campaign_id']}\n"
        f"Attack Type: {ctx['attack_type']}\n"
        f"Source IPs: {', '.join(ctx['source_ips'])}\n"
        f"Destination Port: {ctx['destination_port']}\n"
        f"Protocol: {ctx['protocol']}\n"
        f"Event Count: {ctx['event_count']} failed login attempts\n"
        f"Unique Usernames: {ctx['unique_usernames']}\n"
        f"Time Window: {ctx['first_seen']} to {ctx['last_seen']}\n"
        f"Threat Score: {ctx['threat_score']} / 100\n"
        f"Confidence: {ctx['confidence_score']}\n"
        f"MITRE ATT&CK: {ctx['mitre_technique_id']} ({ctx['mitre_technique_name']})\n"
        f"Tactic: {ctx['mitre_tactic']}\n"
        f"Targeted Usernames: {', '.join(ctx['targeted_usernames'])}\n"
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


def build_prompt_v3_hardened() -> str:
    """V3 — Hardened prompt with anti-hallucination guardrails and format fences."""
    ctx = SSH_TELEMETRY_CONTEXT
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
        f"Target: port {ctx['destination_port']} ({ctx['protocol']})\n"
        f"Events: {ctx['event_count']} failed SSH logins over 15 minutes\n"
        f"Usernames tried: {ctx['unique_usernames']} unique "
        f"(including: {', '.join(ctx['targeted_usernames'][:4])})\n"
        f"Window: {ctx['first_seen']} — {ctx['last_seen']}\n"
        f"Threat Score: {ctx['threat_score']}/100 | Confidence: {ctx['confidence_score']}\n"
        f"MITRE: {ctx['mitre_technique_id']} — {ctx['mitre_technique_name']} "
        f"({ctx['mitre_tactic']})\n"
        f"Reference: {ctx['mitre_url']}\n"
        f"Snort Signature: {ctx['snort_rule']}\n"
        "--- END TELEMETRY ---"
    )


PROMPT_VARIANTS = [
    {"name": "V1 — Raw Telemetry (Baseline)", "builder": build_prompt_v1_raw},
    {"name": "V2 — Structured Sections", "builder": build_prompt_v2_structured},
    {"name": "V3 — Hardened Anti-Hallucination", "builder": build_prompt_v3_hardened},
]

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

KNOWN_IPS = set(SSH_TELEMETRY_CONTEXT["source_ips"])
KNOWN_PORT = str(SSH_TELEMETRY_CONTEXT["destination_port"])
KNOWN_TECHNIQUE = SSH_TELEMETRY_CONTEXT["mitre_technique_id"]


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


def check_factual_accuracy(text: str) -> Dict[str, Any]:
    """Check for hallucinated data not in the original telemetry."""
    checks = {}

    # Check known IPs are referenced
    ips_found = [ip for ip in KNOWN_IPS if ip in text]
    checks["known_ips_referenced"] = ips_found
    checks["known_ips_coverage"] = len(ips_found) / len(KNOWN_IPS)

    # Check for fabricated IPs (IPs not in our telemetry)
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    all_ips = set(ip_pattern.findall(text))
    # Filter out common non-IP patterns and known IPs
    fabricated_ips = all_ips - KNOWN_IPS - {"0.0.0.0", "255.255.255.255", "127.0.0.1"}
    checks["fabricated_ips"] = list(fabricated_ips)
    checks["has_fabricated_ips"] = len(fabricated_ips) > 0

    # Check port reference
    checks["correct_port_referenced"] = KNOWN_PORT in text

    # Check MITRE technique
    checks["correct_technique_referenced"] = KNOWN_TECHNIQUE in text

    # Check for hallucinated metrics
    checks["correct_event_count"] = "450" in text
    checks["correct_username_count"] = "120" in text

    return checks


def check_security_compliance(text: str) -> Dict[str, Any]:
    """Check security-relevant content quality."""
    checks = {}
    text_lower = text.lower()

    checks["mentions_containment"] = any(
        w in text_lower for w in ["block", "isolate", "firewall", "containment", "quarantine"]
    )
    checks["mentions_monitoring"] = any(
        w in text_lower for w in ["monitor", "logging", "audit", "alert"]
    )
    checks["mentions_credential_hygiene"] = any(
        w in text_lower for w in ["password", "credential", "mfa", "authentication", "key-based"]
    )
    checks["mentions_mitre_tactic"] = "credential access" in text_lower
    checks["references_snort_or_ids"] = any(
        w in text_lower for w in ["snort", "ids", "intrusion detection", "signature"]
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
    score += 2 if accuracy["correct_username_count"] else 0

    # Compliance (25 points)
    score += 5 if compliance["mentions_containment"] else 0
    score += 5 if compliance["mentions_monitoring"] else 0
    score += 5 if compliance["mentions_credential_hygiene"] else 0
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
# Ollama interaction
# ---------------------------------------------------------------------------

def send_to_ollama(
    base_url: str, model: str, prompt: str, temperature: float = 0.15
) -> Optional[Dict[str, Any]]:
    """Send prompt to Ollama and return response + timing metrics."""
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
        print("  ERROR: Cannot reach Ollama. Is the daemon running?")
        return None
    except requests.Timeout:
        print("  ERROR: Request timed out (120s)")
        return None
    except Exception as exc:
        print(f"  ERROR: {exc}")
        return None


# ---------------------------------------------------------------------------
# Main evaluation pipeline
# ---------------------------------------------------------------------------

def run_evaluation(base_url: str, model: str) -> Dict[str, Any]:
    """Run all prompt variants and evaluate each response."""
    print()
    print("=" * 72)
    print("  PhantomNet — LLM Quality Evaluation: SSH Brute Force Summaries")
    print("=" * 72)
    print(f"  Host:  {base_url}")
    print(f"  Model: {model}")
    print(f"  Time:  {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    results = {
        "metadata": {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "model": model,
            "ollama_host": base_url,
            "telemetry_context": SSH_TELEMETRY_CONTEXT,
        },
        "evaluations": [],
    }

    for variant in PROMPT_VARIANTS:
        name = variant["name"]
        prompt = variant["builder"]()

        print(f"\n{'─' * 72}")
        print(f"  Prompt: {name}")
        print(f"  Prompt length: {len(prompt)} chars / ~{len(prompt.split())} words")
        print(f"{'─' * 72}")

        response_data = send_to_ollama(base_url, model, prompt)

        if not response_data:
            results["evaluations"].append({
                "prompt_name": name,
                "status": "FAILED",
                "error": "Ollama request failed",
            })
            continue

        raw_output = response_data["response"]
        print(f"  Response: {response_data['eval_count']} tokens in {response_data['wall_time_s']}s")
        print(f"  Speed:    {response_data['tokens_per_sec']} tok/s")

        # Run quality checks
        structure = check_markdown_structure(raw_output)
        accuracy = check_factual_accuracy(raw_output)
        compliance = check_security_compliance(raw_output)
        score, grade = compute_quality_score(structure, accuracy, compliance)

        print(f"  Score:    {score}/100 (Grade: {grade})")
        print(f"  Sections: {len(structure['sections_found'])}/{len(REQUIRED_SECTIONS)}")

        if structure["sections_missing"]:
            print(f"  Missing:  {', '.join(structure['sections_missing'])}")
        if accuracy["has_fabricated_ips"]:
            print(f"  WARNING:  Fabricated IPs detected: {accuracy['fabricated_ips']}")

        evaluation = {
            "prompt_name": name,
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
        best = max(successful, key=lambda e: e["composite_score"])
        results["summary"] = {
            "total_variants_tested": len(PROMPT_VARIANTS),
            "successful": len(successful),
            "best_prompt": best["prompt_name"],
            "best_score": best["composite_score"],
            "best_grade": best["grade"],
        }
        print(f"\n{'=' * 72}")
        print(f"  BEST PROMPT: {best['prompt_name']}")
        print(f"  BEST SCORE:  {best['composite_score']}/100 (Grade {best['grade']})")
        print(f"{'=' * 72}\n")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PhantomNet LLM Quality Evaluation — SSH Brute Force"
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
        "--output", default="reports/llm_ssh_bf_quality_report.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    # Health check
    print(f"Checking Ollama at {args.host}...")
    try:
        resp = requests.get(args.host, timeout=5)
        if resp.status_code != 200:
            raise ConnectionError()
        print("Ollama is responsive.")
    except Exception:
        print(f"ERROR: Cannot reach Ollama at {args.host}")
        print("Ensure Ollama is running: docker compose up -d ollama")
        sys.exit(1)

    results = run_evaluation(args.host, args.model)

    # Save report
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
