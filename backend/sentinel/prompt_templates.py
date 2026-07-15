"""
backend/sentinel/prompt_templates.py
--------------------------------------
PhantomNet Sentinel Layer — Structured Prompt Template Constants

Provides structured, markdown-oriented prompt templates for the local LLM
(Ollama/Mistral) that safely inject security incident context for narrative
summaries.

Design Principles
-----------------
- All prompt strings are stored as module-level constants so they can be
  imported and unit-tested without file I/O.
- UTC timestamps are ALWAYS normalised before injection via
  ``normalise_utc_timestamp()`` to guarantee consistent ISO-8601 UTC format.
- Jinja2 templates in ``backend/sentinel/templates/narrative_prompt.md.j2``
  are the canonical rendering path; the constants in this module are the
  fallback / programmatic path and serve as authoritative documentation.

Structured Sections
-------------------
1. SECTION_CAMPAIGN_CLUSTER_METADATA — Campaign Cluster Metadata table.
2. SECTION_SOURCE_IPS_IOCS          — Source IPs / IOC list.
3. SECTION_MITRE_ATTACK_MAPPING     — MITRE ATT&CK technique mapping table.
4. SECTION_MITIGATION_STEPS         — Actionable mitigation steps.
5. FULL_NARRATIVE_PROMPT_TEMPLATE   — Composite full prompt combining all
                                      sections with system instruction header.

Public API
----------
normalise_utc_timestamp(ts) -> str
    Convert any timestamp (str/datetime/None) to UTC ISO-8601 string.

build_narrative_prompt(context) -> str
    Build the full structured prompt string from a context dict.

render_narrative_prompt_jinja(context) -> str
    Render the prompt via the Jinja2 template file (preferred path).

Week 17, Day 2 — Structured Prompt Templates
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentinel.prompt_templates")

# ---------------------------------------------------------------------------
# UTC Timestamp Standardization
# ---------------------------------------------------------------------------

_UTC_ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def normalise_utc_timestamp(
    ts: Optional[Any],
    *,
    fallback_now: bool = True,
) -> str:
    """Normalise any timestamp input to a UTC ISO-8601 string.

    Ensures all prompt inputs use a consistent timestamp format
    (``YYYY-MM-DDTHH:MM:SSZ``) regardless of the input type.

    Parameters
    ----------
    ts : str | datetime | None
        Input timestamp. Accepted forms:
        - ISO-8601 string with or without timezone offset
        - ``datetime`` object (aware or naive; naive assumed UTC)
        - ``None`` — returns ``datetime.now(UTC)`` when ``fallback_now=True``
    fallback_now : bool
        When ``True`` (default), return the current UTC time if ``ts`` is
        ``None`` or cannot be parsed. When ``False``, return ``"N/A"``.

    Returns
    -------
    str
        UTC timestamp string in ``YYYY-MM-DDTHH:MM:SSZ`` format, or
        ``"N/A"`` when ``fallback_now=False`` and input is invalid.

    Examples
    --------
    >>> normalise_utc_timestamp("2026-07-14T10:00:00+05:30")
    '2026-07-14T04:30:00Z'
    >>> normalise_utc_timestamp(None)  # returns current UTC time
    '2026-07-14T...'
    """
    if ts is None:
        if fallback_now:
            return datetime.now(timezone.utc).strftime(_UTC_ISO_FORMAT)
        return "N/A"

    if isinstance(ts, datetime):
        # Naive datetime → assume UTC
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).strftime(_UTC_ISO_FORMAT)

    if isinstance(ts, str):
        ts_str = ts.strip()
        if not ts_str:
            if fallback_now:
                return datetime.now(timezone.utc).strftime(_UTC_ISO_FORMAT)
            return "N/A"

        # Try parsing ISO-8601 variants
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",   # with offset e.g. +05:30
            "%Y-%m-%dT%H:%M:%SZ",    # explicit Z
            "%Y-%m-%dT%H:%M:%S",     # naive ISO
            "%Y-%m-%d %H:%M:%S%z",   # with space separator
            "%Y-%m-%d %H:%M:%S",     # naive with space
            "%Y-%m-%d",              # date only
        ):
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).strftime(_UTC_ISO_FORMAT)
            except ValueError:
                continue

        # Try Python 3.7+ fromisoformat (handles most edge cases)
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime(_UTC_ISO_FORMAT)
        except (ValueError, AttributeError):
            pass

    logger.warning(
        "normalise_utc_timestamp: could not parse %r — using %s",
        ts,
        "now(UTC)" if fallback_now else "'N/A'",
    )
    if fallback_now:
        return datetime.now(timezone.utc).strftime(_UTC_ISO_FORMAT)
    return "N/A"


# ---------------------------------------------------------------------------
# Section 1: Campaign Cluster Metadata
# ---------------------------------------------------------------------------

SECTION_CAMPAIGN_CLUSTER_METADATA: str = """\
## 1. Campaign Cluster Metadata

| Field              | Value                       |
|--------------------|-----------------------------|
| Campaign ID        | {campaign_id}               |
| Generated At (UTC) | {generated_at_utc}          |
| Event Count        | {event_count}               |
| Service Type       | {service_type}              |
| Protocol           | {protocol}                  |
| Target Ports       | {target_ports}              |
| Confidence Score   | {confidence_score}          |
| Severity           | {severity}                  |
| Time Range Start   | {time_range_start}          |
| Time Range End     | {time_range_end}            |
"""

# ---------------------------------------------------------------------------
# Section 2: Source IPs / IOCs
# ---------------------------------------------------------------------------

SECTION_SOURCE_IPS_IOCS: str = """\
## 2. Source IPs / Indicators of Compromise (IOCs)

The following source IPs and IOC entries were identified as part of this
campaign cluster:

### Source IPs
{source_ips_list}

### Additional IOC Entries
{ioc_table}
"""

# ---------------------------------------------------------------------------
# Section 3: MITRE ATT&CK Mapping
# ---------------------------------------------------------------------------

SECTION_MITRE_ATTACK_MAPPING: str = """\
## 3. MITRE ATT&CK Mapping

| Field          | Value                |
|----------------|----------------------|
| Technique ID   | {technique_id}       |
| Technique Name | {technique_name}     |
| Tactic         | {tactic}             |
| Reference URL  | {mitre_url}          |
| Threat Score   | {threat_score}       |

### All Detected Techniques
{all_techniques_list}
"""

# ---------------------------------------------------------------------------
# Section 4: Mitigation Steps
# ---------------------------------------------------------------------------

SECTION_MITIGATION_STEPS: str = """\
## 4. Mitigation Steps

Based on the detected attack pattern and MITRE ATT&CK technique
**{technique_id} — {technique_name}**, the following mitigations are
recommended:

{mitigation_steps}
"""

# Mitigation step presets keyed by service type
_MITIGATION_PRESETS: Dict[str, str] = {
    "SSH": (
        "1. **Block Source IPs** — Immediately add all identified source IPs "
        "to the perimeter firewall deny-list.\n"
        "2. **Rotate SSH Credentials** — Force rotation of all SSH keys and "
        "passwords for affected accounts.\n"
        "3. **Rate-Limit SSH Connections** — Apply connection-rate limits "
        "(≤ 3 attempts/min/IP) at the network boundary.\n"
        "4. **Enable SSH MFA** — Enforce multi-factor authentication on all "
        "exposed SSH services.\n"
        "5. **Review Audit Logs** — Correlate failed SSH authentication logs "
        "against source IPs for lateral movement indicators."
    ),
    "HTTP": (
        "1. **Block Source IPs** — Deny all HTTP requests from attacker IPs "
        "at the WAF and perimeter firewall.\n"
        "2. **Apply WAF Rules** — Enable SQL injection, XSS, and "
        "scanner-pattern blocking rules in the WAF.\n"
        "3. **Patch Vulnerable Endpoints** — Review and patch all web "
        "application endpoints targeted by the attack.\n"
        "4. **Enable Rate Limiting** — Configure HTTP request rate limits to "
        "prevent automated scanning.\n"
        "5. **Review Access Logs** — Analyse HTTP access logs for evidence of "
        "successful exploitation or data exfiltration."
    ),
    "FTP": (
        "1. **Block Source IPs** — Deny FTP connections from identified "
        "attacker source IPs at the firewall.\n"
        "2. **Disable Anonymous FTP** — Ensure anonymous FTP access is "
        "disabled on all nodes.\n"
        "3. **Audit FTP Transfers** — Review FTP transfer logs for "
        "unauthorised file uploads or downloads.\n"
        "4. **Enforce TLS** — Require FTPS (FTP over TLS) for all "
        "communications.\n"
        "5. **Rotate FTP Credentials** — Immediately rotate FTP account "
        "passwords for affected services."
    ),
    "SMTP": (
        "1. **Block Source IPs** — Deny SMTP connections from identified "
        "attacker source IPs at the MTA and firewall.\n"
        "2. **Enable SPF/DKIM/DMARC** — Verify and enforce email "
        "authentication policies to prevent spoofing.\n"
        "3. **Scan Outbound Mail** — Enable DLP scanning on outbound mail "
        "for data exfiltration indicators.\n"
        "4. **Rate-Limit SMTP** — Apply per-IP and per-sender rate limits "
        "at the mail relay.\n"
        "5. **Review Mail Logs** — Audit SMTP logs for anomalous relay "
        "patterns or bulk sending behaviour."
    ),
    "UNKNOWN": (
        "1. **Block Source IPs** — Add all identified source IPs to the "
        "perimeter firewall deny-list immediately.\n"
        "2. **Segment Network** — Isolate affected network segments to "
        "prevent lateral movement.\n"
        "3. **Collect Evidence** — Preserve packet captures and log files "
        "for forensic analysis.\n"
        "4. **Notify Stakeholders** — Escalate the incident to the "
        "appropriate security response teams.\n"
        "5. **Review Detection Coverage** — Ensure IDS/IPS signatures and "
        "SIEM correlation rules cover the detected technique."
    ),
}


def get_mitigation_steps(service_type: str) -> str:
    """Return the recommended mitigation steps string for a given service type.

    Parameters
    ----------
    service_type : str
        One of ``SSH``, ``HTTP``, ``FTP``, ``SMTP``, or ``UNKNOWN``.

    Returns
    -------
    str
        Numbered Markdown list of mitigation steps.
    """
    return _MITIGATION_PRESETS.get(
        (service_type or "UNKNOWN").upper(),
        _MITIGATION_PRESETS["UNKNOWN"],
    )


# ---------------------------------------------------------------------------
# System Instruction Header
# ---------------------------------------------------------------------------

SYSTEM_INSTRUCTION_HEADER: str = """\
You are a senior cybersecurity incident response analyst. Analyse the
following structured security incident context and produce a professional,
concise narrative summary suitable for inclusion in an incident response
playbook.

The narrative MUST be formatted in Markdown and MUST include:
1. **Executive Summary** — 2–3 sentence overview of the threat.
2. **Attack Narrative** — Description of the attack lifecycle and behaviour.
3. **Containment & Mitigation Steps** — Numbered actionable steps.
4. **Analyst Notes** — Key observations or concerns for follow-up.

Keep the total response under 500 words. Do NOT fabricate IOCs or technique
IDs — only use the data provided below.

---
"""

# ---------------------------------------------------------------------------
# Full composite prompt template
# ---------------------------------------------------------------------------

FULL_NARRATIVE_PROMPT_TEMPLATE: str = (
    SYSTEM_INSTRUCTION_HEADER
    + "\n"
    + SECTION_CAMPAIGN_CLUSTER_METADATA
    + "\n"
    + SECTION_SOURCE_IPS_IOCS
    + "\n"
    + SECTION_MITRE_ATTACK_MAPPING
    + "\n"
    + SECTION_MITIGATION_STEPS
    + "\n---\n"
    + "*Prompt generated by PhantomNet Sentinel LLM Service — Week 17, Day 2*\n"
    + "*UTC Timestamp: {generated_at_utc}*\n"
)


# ---------------------------------------------------------------------------
# Helper: build source IPs list Markdown
# ---------------------------------------------------------------------------

def _format_source_ips(source_ips: List[str]) -> str:
    """Format source IP list as Markdown bullet list."""
    if not source_ips:
        return "_No source IPs recorded for this campaign._"
    return "\n".join(f"- `{ip}`" for ip in source_ips)


# ---------------------------------------------------------------------------
# Helper: build IOC table Markdown
# ---------------------------------------------------------------------------

def _format_ioc_table(ioc_entries: List[Dict[str, Any]]) -> str:
    """Format IOC entries as a Markdown table.

    Parameters
    ----------
    ioc_entries : list[dict]
        Each entry may contain ``type``, ``value``, and ``threat_level`` keys.

    Returns
    -------
    str
        Markdown table string, or a placeholder if no entries provided.
    """
    if not ioc_entries:
        return "_No additional IOC entries for this campaign._"
    rows = ["| Type | Value | Threat Level |", "|------|-------|--------------|"]
    for ioc in ioc_entries:
        ioc_type = str(ioc.get("type", "unknown")).upper()
        ioc_value = str(ioc.get("value", "N/A"))
        threat_lvl = str(ioc.get("threat_level", "Unknown"))
        rows.append(f"| {ioc_type} | `{ioc_value}` | {threat_lvl} |")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Helper: build all-techniques list Markdown
# ---------------------------------------------------------------------------

def _format_all_techniques(techniques: List[Dict[str, Any]]) -> str:
    """Format a list of MITRE techniques as Markdown bullet list."""
    if not techniques:
        return "_No additional technique mappings recorded._"
    lines = []
    for t in techniques:
        tid = t.get("technique_id", "N/A")
        tname = t.get("technique_name", "N/A")
        tactic = t.get("tactic", "N/A")
        lines.append(f"- **{tid}** — {tname} (Tactic: {tactic})")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API: build_narrative_prompt()
# ---------------------------------------------------------------------------

def build_narrative_prompt(context: Dict[str, Any]) -> str:
    """Build a fully structured LLM prompt string from a context dictionary.

    This is the primary programmatic API for constructing prompts.  It
    combines all four structured sections into a single, safe prompt string
    with UTC timestamp standardisation applied to all time fields.

    Parameters
    ----------
    context : dict
        Security incident context. Recognised keys:

        Campaign Cluster Metadata
        - ``campaign_id``      (str)   Campaign cluster identifier.
        - ``generated_at``     (any)   Timestamp of prompt generation (normalised to UTC).
        - ``event_count``      (int)   Number of events in the cluster.
        - ``service_type``     (str)   Inferred service: SSH | HTTP | FTP | SMTP | UNKNOWN.
        - ``protocol``         (str)   Network protocol, e.g. "TCP".
        - ``target_ports``     (list)  List of destination port integers.
        - ``confidence_score`` (float) Confidence score 0.0–1.0.
        - ``severity``         (str)   CRITICAL | HIGH | MEDIUM | LOW.
        - ``time_range_start`` (any)   Campaign start timestamp (normalised to UTC).
        - ``time_range_end``   (any)   Campaign end timestamp (normalised to UTC).

        Source IPs / IOCs
        - ``source_ips``       (list)  List of attacker source IP strings.
        - ``ioc_entries``      (list)  List of IOC dicts with type/value/threat_level.

        MITRE ATT&CK Mapping
        - ``technique_id``     (str)   MITRE technique ID, e.g. "T1110.001".
        - ``technique_name``   (str)   MITRE technique name.
        - ``tactic``           (str)   MITRE tactic name.
        - ``mitre_url``        (str)   Official ATT&CK reference URL.
        - ``threat_score``     (float) ML threat score 0.0–100.0.
        - ``all_techniques``   (list)  All detected technique dicts.

    Returns
    -------
    str
        Fully formatted prompt string ready for submission to the Ollama
        ``/api/generate`` endpoint.

    Notes
    -----
    - All timestamp fields are normalised to UTC ISO-8601 via
      ``normalise_utc_timestamp()`` before injection.
    - No data is fabricated; only values present in ``context`` are used.
    """
    # --- Normalise all UTC timestamps ---
    generated_at_utc = normalise_utc_timestamp(context.get("generated_at"))
    time_range_start = normalise_utc_timestamp(
        context.get("time_range_start") or context.get("time_range", {}).get("start"),
        fallback_now=False,
    )
    time_range_end = normalise_utc_timestamp(
        context.get("time_range_end") or context.get("time_range", {}).get("end"),
        fallback_now=False,
    )

    # --- Extract and sanitise context values ---
    campaign_id = str(context.get("campaign_id") or "UNKNOWN")
    event_count = int(context.get("event_count") or 0)
    service_type = str(context.get("service_type") or "UNKNOWN").upper()
    protocol = str(context.get("protocol") or "TCP").upper()
    target_ports = context.get("target_ports") or []
    target_ports_str = ", ".join(str(p) for p in target_ports) if target_ports else "N/A"

    confidence_score = context.get("confidence_score")
    confidence_str = (
        f"{float(confidence_score):.4f}" if confidence_score is not None else "N/A"
    )
    severity = str(context.get("severity") or "UNKNOWN").upper()

    source_ips: List[str] = list(context.get("source_ips") or [])
    ioc_entries: List[Dict[str, Any]] = list(context.get("ioc_entries") or [])

    technique_id = str(context.get("technique_id") or "N/A")
    technique_name = str(context.get("technique_name") or "N/A")
    tactic = str(context.get("tactic") or "N/A")
    mitre_url = str(
        context.get("mitre_url") or "https://attack.mitre.org/"
    )
    threat_score = context.get("threat_score", 0.0)
    all_techniques: List[Dict[str, Any]] = list(context.get("all_techniques") or [])

    # --- Build individual sections ---
    section1 = SECTION_CAMPAIGN_CLUSTER_METADATA.format(
        campaign_id=campaign_id,
        generated_at_utc=generated_at_utc,
        event_count=event_count,
        service_type=service_type,
        protocol=protocol,
        target_ports=target_ports_str,
        confidence_score=confidence_str,
        severity=severity,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
    )

    section2 = SECTION_SOURCE_IPS_IOCS.format(
        source_ips_list=_format_source_ips(source_ips),
        ioc_table=_format_ioc_table(ioc_entries),
    )

    section3 = SECTION_MITRE_ATTACK_MAPPING.format(
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        mitre_url=mitre_url,
        threat_score=threat_score,
        all_techniques_list=_format_all_techniques(all_techniques),
    )

    mitigation_body = get_mitigation_steps(service_type)
    section4 = SECTION_MITIGATION_STEPS.format(
        technique_id=technique_id,
        technique_name=technique_name,
        mitigation_steps=mitigation_body,
    )

    footer = (
        "\n---\n"
        "*Prompt generated by PhantomNet Sentinel LLM Service — Week 17, Day 2*\n"
        f"*UTC Timestamp: {generated_at_utc}*\n"
    )

    prompt = (
        SYSTEM_INSTRUCTION_HEADER
        + "\n"
        + section1
        + "\n"
        + section2
        + "\n"
        + section3
        + "\n"
        + section4
        + footer
    )

    logger.debug(
        "build_narrative_prompt: built prompt (%d chars) for campaign=%s",
        len(prompt),
        campaign_id,
    )
    return prompt


# ---------------------------------------------------------------------------
# Public API: render_narrative_prompt_jinja()
# ---------------------------------------------------------------------------

def render_narrative_prompt_jinja(context: Dict[str, Any]) -> str:
    """Render the narrative prompt via the Jinja2 template file.

    This is the preferred rendering path when Jinja2 is available.  It
    loads ``backend/sentinel/templates/narrative_prompt.md.j2`` and renders
    it with the provided context, applying UTC timestamp normalisation
    before rendering.

    Falls back to ``build_narrative_prompt()`` if Jinja2 is unavailable
    or the template file cannot be found.

    Parameters
    ----------
    context : dict
        Same context dictionary accepted by ``build_narrative_prompt()``.

    Returns
    -------
    str
        Rendered Markdown prompt string.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        logger.warning(
            "Jinja2 not available — falling back to build_narrative_prompt()"
        )
        return build_narrative_prompt(context)

    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    template_file = "narrative_prompt.md.j2"

    if not os.path.isfile(os.path.join(templates_dir, template_file)):
        logger.warning(
            "Template file %s not found in %s — falling back to build_narrative_prompt()",
            template_file, templates_dir,
        )
        return build_narrative_prompt(context)

    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape([]),  # Markdown — no HTML escaping
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )

    template = env.get_template(template_file)

    # Normalise all timestamps before passing to template
    render_context = dict(context)
    render_context["generated_at_utc"] = normalise_utc_timestamp(
        context.get("generated_at")
    )
    render_context["time_range_start"] = normalise_utc_timestamp(
        context.get("time_range_start")
        or (context.get("time_range") or {}).get("start"),
        fallback_now=False,
    )
    render_context["time_range_end"] = normalise_utc_timestamp(
        context.get("time_range_end")
        or (context.get("time_range") or {}).get("end"),
        fallback_now=False,
    )
    # Ensure list fields are lists
    render_context.setdefault("source_ips", [])
    render_context.setdefault("ioc_entries", [])
    render_context.setdefault("all_techniques", [])
    render_context.setdefault("target_ports", [])

    rendered = template.render(**render_context)
    logger.debug(
        "render_narrative_prompt_jinja: rendered %d chars via %s",
        len(rendered), template_file,
    )
    return rendered
