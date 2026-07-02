"""
backend/sentinel/rule_generator.py
------------------------------------
PhantomNet Sentinel Layer — Snort & Sigma Rule Generator

Generates Snort and Sigma IDS/detection rules from ATT&CK technique data captured by the
Sentinel pipeline. Rules are produced by sentinel_service.py and can be
exported from the Sentinel Dashboard.

Public API
----------
  generate_snort_rule(src_ip, dst_port, protocol, attack_desc,
                      technique_id, sid) -> str
      Generates a single formatted Snort rule string.
      Raises ValueError on invalid inputs.

  generate_sigma_rule(title, logsource, detection, severity,
                      status, tags, technique_id) -> str
      Generates a valid Sigma YAML rule string.
      Raises ValueError on invalid inputs.

  validate_ip(ip_str) -> bool
      Returns True for valid IPv4, CIDR, or Snort keywords (any, $HOME_NET).

  validate_port(port) -> bool
      Returns True for valid port number (0-65535) or 'any'.

  SNORT_RULE_TEMPLATE : str
      The raw template string used for rule generation.
"""

import ipaddress
import os
import re
import threading
import typing
import yaml
import logging

_logger = logging.getLogger("sentinel.rule_generator")

# ---------------------------------------------------------------------------
# ATT&CK Tactic → Sigma Tag Map
# Maps MITRE tactic names to standard Sigma attack.<tactic_slug> tags.
# Reference: https://github.com/SigmaHQ/sigma/blob/master/tags/attack.md
# ---------------------------------------------------------------------------
_TACTIC_SIGMA_TAG: dict[str, str] = {
    "Reconnaissance":        "attack.reconnaissance",
    "Resource Development":  "attack.resource_development",
    "Initial Access":        "attack.initial_access",
    "Execution":             "attack.execution",
    "Persistence":           "attack.persistence",
    "Privilege Escalation":  "attack.privilege_escalation",
    "Defense Evasion":       "attack.defense_evasion",
    "Credential Access":     "attack.credential_access",
    "Discovery":             "attack.discovery",
    "Lateral Movement":      "attack.lateral_movement",
    "Collection":            "attack.collection",
    "Command and Control":   "attack.command_and_control",
    "Exfiltration":          "attack.exfiltration",
    "Impact":                "attack.impact",
}


def get_tactic_sigma_tag(tactic: str) -> "str | None":
    """Return the standard Sigma tactic tag for a MITRE tactic name.

    Examples::

        get_tactic_sigma_tag("Credential Access")  # -> "attack.credential_access"
        get_tactic_sigma_tag("Unknown Tactic")      # -> None

    Args:
        tactic: MITRE ATT&CK tactic name (e.g. "Credential Access").

    Returns:
        Sigma-formatted tactic tag string, or None if the tactic is not mapped.
    """
    if not isinstance(tactic, str):
        return None
    return _TACTIC_SIGMA_TAG.get(tactic.strip())


def _find_data_dir() -> str:
    """Locate the project ``data/`` directory by walking up from this file.

    Searches up to five parent directories from the location of this source
    file.  Falls back to the directory containing this file if no ``data/``
    directory is found.

    Returns:
        Absolute path to the ``data/`` directory.
    """
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        candidate = os.path.join(current, "data")
        if os.path.isdir(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return os.path.dirname(os.path.abspath(__file__))

_BASE_SID = 1000001
_SID_FILE_PATH = os.path.join(_find_data_dir(), "last_sid.txt")

def _load_sid() -> int:
    """Load the last-used Snort SID from persistent storage.

    Reads the SID counter from ``_SID_FILE_PATH``.  Returns
    ``_BASE_SID`` when the file is missing, empty, corrupted, or
    contains an invalid value.

    Returns:
        The next available SID integer.
    """
    if not os.path.exists(_SID_FILE_PATH):
        return _BASE_SID
    try:
        with open(_SID_FILE_PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return _BASE_SID
            val = int(content)
            if val <= 0:
                _logger.warning("Corrupted SID value in storage: %s. Reverting to base SID.", content)
                return _BASE_SID
            return val
    except Exception as e:
        _logger.warning("Error reading SID storage: %s. Reverting to base SID.", e)
        return _BASE_SID

def _save_sid(sid: int) -> None:
    """Persist the current SID counter to ``_SID_FILE_PATH``.

    Creates the parent directory if it does not exist.  Logs an error
    if the write fails but does not raise — SID tracking is
    best-effort.

    Args:
        sid: The SID value to write to storage.
    """
    try:
        os.makedirs(os.path.dirname(_SID_FILE_PATH), exist_ok=True)
        with open(_SID_FILE_PATH, "w", encoding="utf-8") as f:
            f.write(str(sid))
    except Exception as e:
        _logger.error("Failed to write SID to storage: %s", e)

# Thread-safe SID tracking
_sid_lock = threading.Lock()
_NEXT_SID = _load_sid()


def escape_snort_string(val: str) -> str:
    """
    Escape special characters in a Snort string value (double quotes, backslashes, semicolons).
    
    Args:
        val: The raw description string.
        
    Returns:
        The escaped description string suitable for msg field.
    """
    if not isinstance(val, str):
        return ""
    # Escape backslash first to prevent double-escaping
    val = val.replace("\\", "\\\\")
    # Escape double quotes
    val = val.replace('"', '\\"')
    # Escape semicolons to prevent rule option parsing errors
    val = val.replace(";", "\\;")
    return val


def format_mitre_url(technique_id: str) -> str:
    """
    Normalizes a technique ID or MITRE URL into a standard URL path segment.
    
    Examples:
        "T1110.001" -> "T1110/001/"
        "T1190" -> "T1190/"
        "https://attack.mitre.org/techniques/T1110/001/" -> "T1110/001/"
    """
    if not technique_id:
        return ""

    # If it is a full URL, extract the technique portion
    if "attack.mitre.org/techniques/" in technique_id:
        parts = technique_id.split("attack.mitre.org/techniques/")
        if len(parts) > 1:
            technique_id = parts[1]

    # Remove protocol if present
    if technique_id.startswith("https://"):
        technique_id = technique_id[8:]
    elif technique_id.startswith("http://"):
        technique_id = technique_id[7:]

    # Clean leading/trailing slashes for processing
    technique_id = technique_id.strip("/")

    # Replace dots with slashes
    path = technique_id.replace(".", "/")
    
    # Ensure trailing slash is present
    if path and not path.endswith("/"):
        path += "/"
        
    return path


# ---------------------------------------------------------------------------
# Snort Rule Template
# Fields: protocol, src_ip, dst_port, attack_desc, technique_id, sid
# ---------------------------------------------------------------------------
SNORT_RULE_TEMPLATE = (
    'alert {protocol} {src_ip} any -> $HOME_NET {dst_port} ('
    'msg:"{attack_desc}"; '
    'flow:to_server,established; '
    'threshold:type limit, track by_src, count 5, seconds 60; '
    'classtype:attempted-admin; '
    'reference:url,attack.mitre.org/techniques/{technique_id}; '
    'sid:{sid}; '
    'rev:1;'
    ')'
)


def validate_ip(ip_str: str) -> bool:
    """Validate if the string is a valid IP address or allowed variable/keyword.

    Accepts valid IPv4/IPv6 addresses, CIDR notation, and Snort keywords
    (``any``, ``$EXTERNAL_NET``, ``$HOME_NET``).

    Args:
        ip_str: String to validate as an IP address or keyword.

    Returns:
        True if the input is a valid IP, CIDR, or Snort keyword.
    """
    if not isinstance(ip_str, str):
        return False
    if ip_str.lower() in ("any", "$external_net", "$home_net"):
        return True
    try:
        # Check if it's a valid CIDR network
        if '/' in ip_str:
            ipaddress.ip_network(ip_str, strict=False)
        else:
            ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        _logger.debug("IP validation failed for: %s", ip_str)
        return False


def validate_port(port: typing.Union[int, str]) -> bool:
    """Validate if the port is a valid port number (0–65535) or the keyword ``'any'``.

    Args:
        port: Integer port number or string (``'any'`` or numeric string).

    Returns:
        True if the port is valid.
    """
    if isinstance(port, str) and port.lower() == "any":
        return True
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (TypeError, ValueError):
        _logger.debug("Port validation failed for: %s", port)
        return False


def generate_snort_rule(
    src_ip: str,
    dst_port: typing.Union[int, str],
    protocol: str,
    attack_desc: str,
    technique_id: str,
    sid: typing.Optional[int] = None,
) -> str:
    """
    Generates a Snort rule string based on the provided parameters.

    Args:
        src_ip:       Source IP address (e.g., '192.168.1.1', 'any', '$EXTERNAL_NET')
        dst_port:     Destination port (e.g., 22, 80, 'any')
        protocol:     Network protocol (e.g., 'tcp', 'udp', 'icmp')
        attack_desc:  Description of the attack for the 'msg' field
        technique_id: MITRE ATT&CK technique ID for the 'reference' field
        sid:          Optional Snort rule ID. If None, auto-increments.

    Returns:
        A formatted Snort rule string.

    Raises:
        ValueError: If input parameters are invalid.
    """
    global _NEXT_SID

    if not validate_ip(src_ip):
        raise ValueError(f"Invalid source IP address: {src_ip}")

    if not validate_port(dst_port):
        raise ValueError(f"Invalid destination port: {dst_port}")

    protocol = protocol.lower()
    if protocol not in ("tcp", "udp", "icmp", "ip"):
        raise ValueError(f"Unsupported protocol: {protocol}")

    # Determine SID using thread-safe block
    with _sid_lock:
        if sid is None:
            sid_to_use = _NEXT_SID
            _NEXT_SID += 1
        else:
            try:
                sid_to_use = int(sid)
                if sid_to_use <= 0:
                    raise ValueError("SID must be a positive integer")
            except ValueError:
                raise ValueError(f"Invalid SID: {sid}")

            # Advance next SID if explicit SID is equal or greater, preventing future collisions
            if sid_to_use >= _NEXT_SID:
                _NEXT_SID = sid_to_use + 1

        # Persist the new SID counter value
        _save_sid(_NEXT_SID)

    # Escape attack description to keep Snort syntax valid
    escaped_desc = escape_snort_string(attack_desc)
    
    # Format technique ID properly for the MITRE URL reference
    formatted_tech_id = format_mitre_url(technique_id)

    rule = SNORT_RULE_TEMPLATE.format(
        protocol=protocol,
        src_ip=src_ip,
        dst_port=dst_port,
        attack_desc=escaped_desc,
        technique_id=formatted_tech_id,
        sid=sid_to_use,
    )

    return rule


def clean_and_format_tag(tag: str) -> str:
    """
    Normalizes a tag or MITRE ATT&CK technique reference into a standard lowercase Sigma tag.
    
    Examples:
        "T1110.001" -> "attack.t1110.001"
        "T1190" -> "attack.t1190"
        "https://attack.mitre.org/techniques/T1110/001/" -> "attack.t1110.001"
        "honeypot" -> "honeypot"
    """
    if not isinstance(tag, str):
        return ""
    
    tag_clean = tag.strip()
    
    # If it is a full MITRE URL, extract the technique portion
    if "attack.mitre.org/techniques/" in tag_clean:
        parts = tag_clean.split("attack.mitre.org/techniques/")
        if len(parts) > 1:
            tag_clean = parts[1]
            
    # Clean leading/trailing slashes
    tag_clean = tag_clean.strip("/")
    
    # Check if it matches the ATT&CK technique pattern (e.g. t1110, t1110.001, t1110/001, optionally with attack. prefix)
    pattern = r"^(?:attack\.)?([tT]\d{4}(?:[./]\d{3})?)$"
    match = re.match(pattern, tag_clean)
    if match:
        tech_id = match.group(1).lower().replace("/", ".")
        return f"attack.{tech_id}"
    
    # If it starts with attack. but is not standard technique pattern, just return lowercase
    if tag_clean.lower().startswith("attack."):
        return tag_clean.lower()
        
    return tag_clean.lower()


def map_severity_to_level(severity: str) -> str:
    """
    Maps a severity string to a standard Sigma level (critical, high, medium, low).
    
    Supported severity values (case-insensitive):
        - CRITICAL -> critical
        - HIGH -> high
        - MEDIUM -> medium
        - LOW -> low
        - INFO -> low
    """
    if not isinstance(severity, str):
        return "medium"
        
    sev = severity.strip().lower()
    if sev in ("critical", "high", "medium", "low"):
        return sev
    if sev == "info":
        return "low"
        
    # Default to medium if unknown
    return "medium"


def generate_sigma_rule(
    title: str,
    logsource: dict,
    detection: dict,
    severity: str,
    status: str = "experimental",
    tags: typing.Optional[typing.Union[str, list[str]]] = None,
    technique_id: typing.Optional[str] = None,
    tactic: typing.Optional[str] = None,
) -> str:
    """
    Generates a valid Sigma rule in YAML format.

    Args:
        title:        Title of the rule (must be non-empty string).
        logsource:    Dictionary of logsource properties (must be non-empty dict).
        detection:    Dictionary of detection criteria (must be non-empty dict).
        severity:     Severity string (must be mapped to critical/high/medium/low).
        status:       Status of the rule (default: 'experimental').
        tags:         Optional tags (list of strings or space/comma separated string).
        technique_id: Optional MITRE ATT&CK technique ID or URL to format as an attack tag.
        tactic:       Optional MITRE ATT&CK tactic name (e.g. "Credential Access").
                      When provided the corresponding Sigma tactic tag is automatically
                      appended (e.g. "attack.credential_access") alongside the technique
                      tag, satisfying the Sigma ATT&CK tag specification.

    Returns:
        A valid YAML string representing the Sigma rule.

    Raises:
        ValueError: If input validation fails.
    """
    if not title or not isinstance(title, str) or not title.strip():
        raise ValueError("Title must be a non-empty string.")

    if not isinstance(logsource, dict) or not logsource:
        raise ValueError("Logsource must be a non-empty dictionary.")

    if not isinstance(detection, dict) or not detection:
        raise ValueError("Detection block must be a non-empty dictionary.")

    if not severity or not isinstance(severity, str) or not severity.strip():
        raise ValueError("Severity must be a non-empty string.")

    if not isinstance(status, str) or not status.strip():
        raise ValueError("Status must be a non-empty string.")

    # Map severity to Sigma level
    level = map_severity_to_level(severity)

    # Process and format tags
    processed_tags = []
    
    # 1. Process technique_id if provided
    if technique_id:
        tech_tag = clean_and_format_tag(technique_id)
        if tech_tag:
            processed_tags.append(tech_tag)

    # 2. Process other tags
    if tags:
        if isinstance(tags, str):
            # Split by commas first, then by whitespaces
            raw_tags = [t.strip() for t in tags.replace(",", " ").split() if t.strip()]
        elif isinstance(tags, list):
            raw_tags = [str(t) for t in tags if t]
        else:
            raw_tags = []

        for t in raw_tags:
            formatted = clean_and_format_tag(t)
            if formatted and formatted not in processed_tags:
                processed_tags.append(formatted)

    # 3. Auto-inject tactic tag from tactic name (Sigma ATT&CK tag spec requirement).
    #    This ensures every rule has BOTH attack.<technique_id> AND attack.<tactic_name>.
    if tactic:
        tactic_tag = get_tactic_sigma_tag(tactic)
        if tactic_tag and tactic_tag not in processed_tags:
            processed_tags.append(tactic_tag)

    # Structure detection block (handle search identifiers and condition)
    detection_copy = dict(detection)
    if "condition" not in detection_copy:
        # Check if it has a flat list of fields or nested search identifiers
        is_flat = False
        for k, v in detection_copy.items():
            if not isinstance(v, (dict, list)):
                is_flat = True
                break
        if is_flat:
            detection_copy = {
                "selection": detection_copy,
                "condition": "selection"
            }
        else:
            if "selection" in detection_copy:
                detection_copy["condition"] = "selection"
            else:
                # Use all keys except 'condition'
                keys = [k for k in detection_copy.keys() if k != "condition"]
                if keys:
                    detection_copy["condition"] = " or ".join(keys)
                else:
                    detection_copy["condition"] = "selection"

    # Construct standard ordered Sigma rule dict
    sigma_rule = {
        "title": title.strip(),
        "status": status.strip().lower(),
        "logsource": logsource,
        "detection": detection_copy,
        "level": level,
    }

    if processed_tags:
        sigma_rule["tags"] = processed_tags

    # Dump to valid YAML string preserving insertion order (sort_keys=False)
    return yaml.safe_dump(sigma_rule, sort_keys=False, default_flow_style=False)


def generate_rules_for_campaign(
    cluster_data: typing.Dict[str, typing.Any],
    mitre_info: typing.Union[typing.List[typing.Dict[str, typing.Any]], typing.Dict[str, typing.Any], None],
) -> typing.Dict[str, typing.Any]:
    """
    Generates Snort and Sigma detection rules for a full campaign cluster.

    Args:
        cluster_data: Dict containing campaign clustering details.
        mitre_info: Technique mapper output (list of technique dicts, single technique dict,
                    or mapping of signature names to technique dicts).

    Returns:
        A dictionary with generated Snort and Sigma rules and rule metadata.
    """
    # 1. Normalize cluster_data
    if not isinstance(cluster_data, dict):
        cluster_data = {}

    campaign_id = cluster_data.get("campaign_id") or cluster_data.get("id") or "unknown_campaign"
    cluster_id = cluster_data.get("cluster_id")
    if cluster_id is None:
        cluster_id = -1

    # Extract source IPs
    sources_raw = cluster_data.get("unique_sources") or cluster_data.get("source_ips") or cluster_data.get("sources")
    if sources_raw is None:
        sources = ["any"]
    elif isinstance(sources_raw, (str, bytes)):
        sources = [sources_raw]
    elif isinstance(sources_raw, (list, set, tuple)):
        sources = list(sources_raw)
    else:
        sources = [str(sources_raw)]
    
    # Filter/validate source IPs
    validated_sources = []
    for ip in sources:
        ip_str = str(ip).strip()
        if validate_ip(ip_str):
            validated_sources.append(ip_str)
    if not validated_sources:
        validated_sources = ["any"]

    # Extract ports
    ports_raw = cluster_data.get("target_ports") or cluster_data.get("ports") or cluster_data.get("dst_ports")
    if ports_raw is None:
        ports = ["any"]
    elif isinstance(ports_raw, (int, str)):
        ports = [ports_raw]
    elif isinstance(ports_raw, (list, set, tuple)):
        ports = list(ports_raw)
    else:
        ports = [str(ports_raw)]

    # Filter/validate ports
    validated_ports = []
    for port in ports:
        if validate_port(port):
            validated_ports.append(port)
    if not validated_ports:
        validated_ports = ["any"]

    # Extract protocols
    protos_raw = cluster_data.get("protocols") or cluster_data.get("protocol")
    if protos_raw is None:
        protocols = ["tcp"]
    elif isinstance(protos_raw, (str, bytes)):
        protocols = [protos_raw]
    elif isinstance(protos_raw, (list, set, tuple)):
        protocols = list(protos_raw)
    else:
        protocols = [str(protos_raw)]

    # Lowercase and filter supported protocols for Snort
    snort_supported_protocols = []
    for proto in protocols:
        p_lower = str(proto).lower().strip()
        if p_lower in ("tcp", "udp", "icmp", "ip"):
            snort_supported_protocols.append(p_lower)
    if not snort_supported_protocols:
        snort_supported_protocols = ["ip"]

    # 2. Normalize mitre_info
    raw_techniques = []
    if not mitre_info:
        # Fallback to generic technique
        raw_techniques = [{
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactic": "Discovery",
            "url": "https://attack.mitre.org/techniques/T1046/",
            "severity": "MEDIUM"
        }]
    elif isinstance(mitre_info, list):
        raw_techniques = list(mitre_info)
    elif isinstance(mitre_info, dict):
        # Is it a single technique dict?
        is_single = "technique_id" in mitre_info or "id" in mitre_info
        if is_single:
            raw_techniques = [mitre_info]
        else:
            # Assume it maps signature names to technique dicts
            raw_techniques = list(mitre_info.values())
    else:
        # Fallback for unexpected types
        raw_techniques = [str(mitre_info)]

    # Normalize each technique dict and deduplicate by technique_id
    normalized_techniques = []
    seen_technique_ids = set()
    for tech in raw_techniques:
        if not isinstance(tech, dict):
            # If it's a string or other, create a basic placeholder
            tech = {"technique_id": str(tech)}
        
        tech_id = tech.get("technique_id") or tech.get("id") or "T1046"
        # Normalize format
        tech_id = str(tech_id).strip()
        
        if tech_id not in seen_technique_ids:
            seen_technique_ids.add(tech_id)
            
            tech_name = tech.get("technique_name") or tech.get("name") or "Unknown ATT&CK Technique"
            tactic = tech.get("tactic") or "Discovery"
            url = tech.get("url") or tech.get("mitre_url") or f"https://attack.mitre.org/techniques/{tech_id}/"
            severity = tech.get("severity") or "MEDIUM"
            
            normalized_techniques.append({
                "technique_id": tech_id,
                "technique_name": tech_name,
                "tactic": tactic,
                "url": url,
                "severity": severity
            })

    # 3. Generate Snort Rules
    snort_rules_list = []
    # Generate for combinations of unique sources, protocols, target ports, and techniques
    for src_ip in validated_sources:
        for protocol in snort_supported_protocols:
            for dst_port in validated_ports:
                for tech in normalized_techniques:
                    attack_desc = f"Campaign {campaign_id} activity from {src_ip} targeting port {dst_port}: {tech['technique_name']}"
                    rule = generate_snort_rule(
                        src_ip=src_ip,
                        dst_port=dst_port,
                        protocol=protocol,
                        attack_desc=attack_desc,
                        technique_id=tech["technique_id"]
                    )
                    snort_rules_list.append(rule)

    # 4. Generate Sigma Rules
    sigma_rules_list = []
    for tech in normalized_techniques:
        title = f"Campaign {campaign_id} Detection for {tech['technique_name']}"
        logsource = {
            "category": "network_traffic",
            "product": "phantomnet"
        }
        
        # Build detection selection block
        selection = {}
        if validated_sources and validated_sources != ["any"]:
            selection["src_ip"] = validated_sources
        if validated_ports and validated_ports != ["any"]:
            selection["dst_port"] = validated_ports
        
        # Include protocols if any
        protos_cleaned = [p.lower().strip() for p in protocols]
        if protos_cleaned:
            selection["protocol"] = protos_cleaned

        # If selection is empty, default to matching anything (e.g. dummy field)
        if not selection:
            selection["event_type"] = "honeypot_log"

        detection = {
            "selection": selection,
            "condition": "selection"
        }
        
        rule = generate_sigma_rule(
            title=title,
            logsource=logsource,
            detection=detection,
            severity=tech["severity"],
            status="experimental",
            tags=["campaign"],
            technique_id=tech["technique_id"],
            tactic=tech.get("tactic"),  # auto-inject attack.<tactic> tag per Sigma spec
        )
        sigma_rules_list.append(rule)

    # 5. Format and return results
    return {
        "snort_rules": "\n".join(snort_rules_list),
        "sigma_rules": "---\n".join(sigma_rules_list),
        "snort_rules_list": snort_rules_list,
        "sigma_rules_list": sigma_rules_list,
        "metadata": {
            "campaign_id": campaign_id,
            "cluster_id": cluster_id,
            "snort_rule_count": len(snort_rules_list),
            "sigma_rule_count": len(sigma_rules_list),
            "unique_sources": validated_sources,
            "target_ports": validated_ports,
            "protocols": list(protocols),
            "techniques": list(seen_technique_ids),
        }
    }


