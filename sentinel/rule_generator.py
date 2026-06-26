"""
sentinel/rule_generator.py
--------------------------
Generates Snort IDS rules and Sigma detection rules from threat intelligence
data. Provides helper utilities for validation, escaping, and MITRE ATT&CK
technique normalisation.
"""

import re
import threading

import yaml

# ---------------------------------------------------------------------------
# Snort rule template (used by tests to verify placeholder presence)
# ---------------------------------------------------------------------------

SNORT_RULE_TEMPLATE = (
    "alert {protocol} {src_ip} any -> any {dst_port} "
    '(msg:"{attack_desc}"; '
    "flow:to_server,established; "
    "threshold:type limit, track by_src, count 5, seconds 60; "
    "classtype:attempted-admin; "
    "reference:url,attack.mitre.org/techniques/{technique_id}; "
    "sid:{sid}; "
    "rev:1;)"
)

# ---------------------------------------------------------------------------
# Valid Snort layer-4 / layer-3 protocols
# ---------------------------------------------------------------------------

_VALID_PROTOCOLS = {"tcp", "udp", "icmp", "ip"}

# ---------------------------------------------------------------------------
# Thread-safe SID counter
# ---------------------------------------------------------------------------

import os
import logging

_logger = logging.getLogger("sentinel.rule_generator")

def _find_data_dir() -> str:
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
    try:
        os.makedirs(os.path.dirname(_SID_FILE_PATH), exist_ok=True)
        with open(_SID_FILE_PATH, "w", encoding="utf-8") as f:
            f.write(str(sid))
    except Exception as e:
        _logger.error("Failed to write SID to storage: %s", e)

_sid_lock = threading.Lock()
_current_sid = _load_sid() - 1

def _next_auto_sid() -> int:
    """Return the next unique SID (thread-safe, monotonically increasing)."""
    global _current_sid
    with _sid_lock:
        _current_sid += 1
        _save_sid(_current_sid + 1)
        return _current_sid


def _advance_counter_if_needed(explicit_sid: int) -> None:
    """Advance the global counter so future auto-SIDs never collide with an explicit one."""
    global _current_sid
    with _sid_lock:
        if explicit_sid >= _current_sid:
            _current_sid = explicit_sid
            _save_sid(_current_sid + 1)


# ---------------------------------------------------------------------------
# Helper: string escaping for Snort option values
# ---------------------------------------------------------------------------

def escape_snort_string(s) -> str:
    """
    Escape a string for safe embedding inside a Snort option value.

    * Backslashes are doubled: ``\\`` → ``\\\\``
    * Semicolons are escaped:  ``;``  → ``\\;``
    * Double-quotes are escaped: ``"`` → ``\\"``

    Non-string input returns an empty string.
    """
    if not isinstance(s, str):
        return ""
    s = s.replace("\\", "\\\\")
    s = s.replace(";", "\\;")
    s = s.replace('"', '\\"')
    return s


# ---------------------------------------------------------------------------
# Helper: MITRE ATT&CK technique normalisation
# ---------------------------------------------------------------------------

def format_mitre_url(technique_id) -> str:
    """
    Convert a MITRE technique identifier to the path fragment used in Snort
    ``reference`` options.

    Examples
    --------
    ``"T1190"``                                          → ``"T1190/"``
    ``"T1110.001"``                                      → ``"T1110/001/"``
    ``"https://attack.mitre.org/techniques/T1110/001/"`` → ``"T1110/001/"``
    """
    if not technique_id or not isinstance(technique_id, str):
        return ""

    # Full ATT&CK URL — extract the last two path segments
    if technique_id.startswith("http"):
        match = re.search(
            r"techniques/([A-Za-z0-9]+)(?:/([A-Za-z0-9]+))?/?$",
            technique_id,
        )
        if match:
            tid = match.group(1)
            sub = match.group(2)
            return f"{tid}/{sub}/" if sub else f"{tid}/"
        return ""

    # Dotted sub-technique notation: T1110.001
    if "." in technique_id:
        main, sub = technique_id.split(".", 1)
        return f"{main}/{sub}/"

    # Plain technique ID: T1190
    return f"{technique_id}/"


def clean_and_format_tag(tag) -> str:
    """
    Normalise a tag string for use in a Sigma ``tags`` list.

    * Full ATT&CK URLs  → ``"attack.tNNNN"`` or ``"attack.tNNNN.NNN"``
    * Technique IDs     → ``"attack.t1190"`` / ``"attack.t1110.001"``
    * Plain strings     → lowercased as-is
    * Non-string inputs → ``""``
    """
    if not isinstance(tag, str):
        return ""

    # Full URL
    if tag.startswith("http"):
        match = re.search(
            r"techniques/(T\d+)(?:/(\d+))?/?$",
            tag,
            re.IGNORECASE,
        )
        if match:
            tid = match.group(1).lower()
            sub = match.group(2)
            return f"attack.{tid}.{sub}" if sub else f"attack.{tid}"
        return tag.lower()

    # Technique ID: optional sub-technique (T1234 or T1234.001)
    if re.match(r"^T\d+(\.\d+)?$", tag, re.IGNORECASE):
        return "attack." + tag.lower()

    # Plain string
    return tag.lower()


# ---------------------------------------------------------------------------
# Helper: severity → Sigma level
# ---------------------------------------------------------------------------

def map_severity_to_level(severity) -> str:
    """
    Map a free-text severity string to a valid Sigma ``level`` value.

    =========  ========
    Input      Output
    =========  ========
    CRITICAL   critical
    HIGH       high
    MEDIUM     medium
    LOW / INFO low
    *other*    medium
    =========  ========
    """
    if not isinstance(severity, str):
        return "medium"
    s = severity.strip().lower()
    if s == "critical":
        return "critical"
    if s == "high":
        return "high"
    if s == "medium":
        return "medium"
    if s in ("low", "info"):
        return "low"
    return "medium"


# ---------------------------------------------------------------------------
# IP / port validation
# ---------------------------------------------------------------------------

def validate_ip(ip) -> bool:
    """
    Return ``True`` when *ip* is a valid value for a Snort rule header.

    Accepted forms
    --------------
    * ``"any"`` / ``"ANY"``
    * Snort variables: ``"$HOME_NET"``, ``"$EXTERNAL_NET"``, etc.
    * Dotted-decimal IPv4: ``"192.168.1.1"``
    * CIDR notation: ``"10.0.0.0/8"``, ``"0.0.0.0/0"``
    """
    if not isinstance(ip, str) or not ip:
        return False

    # Snort keyword
    if ip.upper() == "ANY":
        return True

    # Snort variable
    if ip.startswith("$"):
        return True

    # CIDR
    if "/" in ip:
        ip_part, prefix_part = ip.split("/", 1)
        try:
            prefix = int(prefix_part)
        except ValueError:
            return False
        if prefix < 0 or prefix > 32:
            return False
        ip = ip_part

    # Dotted-decimal IPv4
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    for octet in octets:
        try:
            val = int(octet)
        except ValueError:
            return False
        if val < 0 or val > 255:
            return False
    return True


def validate_port(port) -> bool:
    """
    Return ``True`` when *port* is a legal Snort port specifier.

    Accepted forms
    --------------
    * ``"any"`` / ``"ANY"``
    * Integer or digit-only string in ``[0, 65535]``
    """
    if isinstance(port, str):
        if port.strip().upper() == "ANY":
            return True
        try:
            port = int(port)
        except (ValueError, TypeError):
            return False

    if not isinstance(port, int):
        return False

    return 0 <= port <= 65535


# ---------------------------------------------------------------------------
# Snort rule generator
# ---------------------------------------------------------------------------

def generate_snort_rule(
    src_ip,
    dst_port,
    protocol,
    attack_desc,
    technique_id,
    sid=None,
) -> str:
    """
    Build and return a syntactically valid Snort 2.x alert rule.

    Parameters
    ----------
    src_ip       : Source IP / CIDR / ``"any"`` / Snort variable.
    dst_port     : Destination port (int or ``"any"``).
    protocol     : One of ``tcp``, ``udp``, ``icmp``, ``ip``.
    attack_desc  : Human-readable description (may contain special chars).
    technique_id : MITRE ATT&CK technique ID or full URL.
    sid          : Explicit positive integer SID; ``None`` auto-generates one.

    Raises
    ------
    ValueError   : On invalid src_ip, dst_port, protocol, or SID ≤ 0.
    """
    # --- validate inputs -----------------------------------------------
    if not validate_ip(src_ip):
        raise ValueError(f"Invalid src_ip: {src_ip!r}")

    if not validate_port(dst_port):
        raise ValueError(f"Invalid dst_port: {dst_port!r}")

    if not isinstance(protocol, str) or protocol.lower() not in _VALID_PROTOCOLS:
        raise ValueError(
            f"Invalid protocol {protocol!r}. Must be one of: {sorted(_VALID_PROTOCOLS)}"
        )

    if sid is not None and sid <= 0:
        raise ValueError(f"SID must be a positive integer, got {sid!r}")

    # --- resolve SID ---------------------------------------------------
    if sid is None:
        sid = _next_auto_sid()
    else:
        _advance_counter_if_needed(sid)

    # --- build rule ----------------------------------------------------
    proto = protocol.lower()
    escaped_desc = escape_snort_string(str(attack_desc) if attack_desc else "")
    mitre_path = format_mitre_url(technique_id)

    rule = (
        f"alert {proto} {src_ip} any -> any {dst_port} "
        f'(msg:"{escaped_desc}"; '
        f"flow:to_server,established; "
        f"threshold:type limit, track by_src, count 5, seconds 60; "
        f"classtype:attempted-admin; "
        f"reference:url,attack.mitre.org/techniques/{mitre_path}; "
        f"sid:{sid}; "
        f"rev:1;)"
    )
    return rule


# ---------------------------------------------------------------------------
# Sigma rule generator
# ---------------------------------------------------------------------------

def generate_sigma_rule(
    title,
    logsource,
    detection,
    severity,
    status: str = "experimental",
    technique_id=None,
    tags=None,
) -> str:
    """
    Build and return a Sigma detection rule serialised as a YAML string.

    Parameters
    ----------
    title        : Human-readable rule title (non-empty string).
    logsource    : ``logsource`` mapping (non-empty dict).
    detection    : ``detection`` mapping.  Flat dicts are auto-wrapped in a
                   ``selection`` key; missing ``condition`` is inferred.
    severity     : Severity string; mapped to ``level`` via
                   :func:`map_severity_to_level`.
    status       : Rule status (default ``"experimental"``).
    technique_id : Optional MITRE technique ID added to ``tags``.
    tags         : Additional tags — list of strings or comma-separated str.

    Raises
    ------
    ValueError   : On missing / empty required arguments.
    """
    # --- validate inputs -----------------------------------------------
    if not isinstance(title, str) or not title.strip():
        raise ValueError("title must be a non-empty string")

    if not logsource or not isinstance(logsource, dict):
        raise ValueError("logsource must be a non-empty dict")

    if not detection or not isinstance(detection, dict):
        raise ValueError("detection must be a non-empty dict")

    if not isinstance(severity, str) or not severity.strip():
        raise ValueError("severity must be a non-empty string")

    if not isinstance(status, str) or not status.strip():
        raise ValueError("status must be a non-empty string")

    # --- normalise detection block -------------------------------------
    det = dict(detection)

    if "condition" not in det:
        # Check if it has a flat list of fields or nested search identifiers
        is_flat = False
        for k, v in det.items():
            if not isinstance(v, (dict, list)):
                is_flat = True
                break
        if is_flat:
            det = {
                "selection": det,
                "condition": "selection"
            }
        else:
            if "selection" in det:
                det["condition"] = "selection"
            else:
                # Use all keys except 'condition'
                keys = [k for k in det.keys() if k != "condition"]
                if keys:
                    det["condition"] = " or ".join(keys)
                else:
                    det["condition"] = "selection"

    # --- build tags list -----------------------------------------------
    all_tags: list[str] = []

    if technique_id:
        cleaned = clean_and_format_tag(technique_id)
        if cleaned:
            all_tags.append(cleaned)

    if tags is not None:
        raw_list: list[str]
        if isinstance(tags, str):
            raw_list = [t.strip() for t in tags.split(",") if t.strip()]
        else:
            raw_list = [str(t) for t in tags]

        for raw in raw_list:
            cleaned = clean_and_format_tag(raw)
            if cleaned and cleaned not in all_tags:
                all_tags.append(cleaned)

    # Deduplicate (order-preserving)
    seen: set[str] = set()
    unique_tags: list[str] = []
    for t in all_tags:
        if t not in seen:
            seen.add(t)
            unique_tags.append(t)

    # --- assemble document ---------------------------------------------
    doc: dict = {
        "title": title,
        "status": status.strip().lower(),
        "logsource": logsource,
        "detection": det,
        "level": map_severity_to_level(severity),
    }
    if unique_tags:
        doc["tags"] = unique_tags

    return yaml.dump(doc, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Campaign-level rule generator
# ---------------------------------------------------------------------------

_FALLBACK_MITRE = {
    "technique_id": "T1046",
    "technique_name": "Network Service Scanning",
    "severity": "MEDIUM",
}

_SIGMA_LOGSOURCE_DEFAULT = {
    "category": "network_connection",
    "product": "zeek",
}


def generate_rules_for_campaign(cluster: dict, mitre) -> dict:
    """
    Generate both Snort and Sigma rules for an entire attack campaign cluster.

    Parameters
    ----------
    cluster : Cluster metadata dict with optional keys:
              ``campaign_id``, ``cluster_id``, ``unique_sources``,
              ``target_ports``, ``protocols``.
    mitre   : MITRE ATT&CK info — ``None``, a single technique dict, or a
              list of technique dicts.  When ``None`` a fallback technique is
              used.

    Returns
    -------
    dict with keys:
      ``snort_rules``      – newline-joined string of all Snort rules
      ``sigma_rules``      – newline-joined string of all Sigma rules
      ``snort_rules_list`` – list of individual Snort rule strings
      ``sigma_rules_list`` – list of individual Sigma rule strings
      ``metadata``         – campaign-level summary dict
    """
    # --- normalise cluster dict ----------------------------------------
    campaign_id = cluster.get("campaign_id", "unknown")
    cluster_id = cluster.get("cluster_id", 0)
    raw_sources = cluster.get("unique_sources", [])
    raw_ports = cluster.get("target_ports", [])
    raw_protocols = cluster.get("protocols", [])

    # --- filter valid sources ------------------------------------------
    valid_sources = [ip for ip in raw_sources if validate_ip(ip)]
    if not valid_sources:
        valid_sources = ["any"]

    # --- filter valid ports --------------------------------------------
    valid_ports = [p for p in raw_ports if validate_port(p)]
    if not valid_ports:
        valid_ports = [80]

    # --- filter valid protocols ----------------------------------------
    valid_protocols = [p for p in raw_protocols if isinstance(p, str) and p.lower() in _VALID_PROTOCOLS]
    if not valid_protocols:
        valid_protocols = ["ip"]

    # --- normalise mitre info ------------------------------------------
    if mitre is None:
        techniques = [_FALLBACK_MITRE]
    elif isinstance(mitre, dict):
        techniques = [mitre]
    else:
        techniques = list(mitre)

    technique_ids = [t.get("technique_id", "T1046") for t in techniques]

    # --- generate Snort rules (cartesian: sources × protocols × ports × techniques) ---
    snort_rules_list: list[str] = []

    for src_ip in valid_sources:
        for proto in valid_protocols:
            for port in valid_ports:
                for tech in techniques:
                    tid = tech.get("technique_id", "T1046")
                    tname = tech.get("technique_name", "Unknown Technique")
                    severity = tech.get("severity", "MEDIUM")
                    desc = f"PhantomNet: {tname}"
                    try:
                        rule = generate_snort_rule(
                            src_ip=src_ip,
                            dst_port=port,
                            protocol=proto,
                            attack_desc=desc,
                            technique_id=tid,
                            sid=None,
                        )
                        snort_rules_list.append(rule)
                    except ValueError:
                        pass  # skip invalid combinations

    # --- generate Sigma rules (one per technique) ----------------------
    sigma_rules_list: list[str] = []

    for tech in techniques:
        tid = tech.get("technique_id", "T1046")
        tname = tech.get("technique_name", "Unknown Technique")
        severity = tech.get("severity", "MEDIUM")

        logsource = _SIGMA_LOGSOURCE_DEFAULT.copy()
        detection = {
            "selection": {
                "src_ip": valid_sources if valid_sources != ["any"] else None,
                "dst_port": valid_ports,
            },
            "condition": "selection",
        }
        # Remove None values
        detection["selection"] = {
            k: v for k, v in detection["selection"].items() if v is not None
        }
        if not detection["selection"]:
            detection["selection"] = {"dst_port": valid_ports}

        try:
            sigma_yaml = generate_sigma_rule(
                title=f"PhantomNet: {tname}",
                logsource=logsource,
                detection=detection,
                severity=severity,
                status="experimental",
                technique_id=tid,
            )
            sigma_rules_list.append(sigma_yaml)
        except ValueError:
            pass

    # --- assemble result -----------------------------------------------
    snort_rules_str = "\n".join(snort_rules_list)
    sigma_rules_str = "\n---\n".join(sigma_rules_list)

    metadata = {
        "campaign_id": campaign_id,
        "cluster_id": cluster_id,
        "snort_rule_count": len(snort_rules_list),
        "sigma_rule_count": len(sigma_rules_list),
        "techniques": technique_ids,
        "valid_sources": valid_sources,
        "valid_ports": valid_ports,
        "valid_protocols": valid_protocols,
    }

    return {
        "snort_rules": snort_rules_str,
        "sigma_rules": sigma_rules_str,
        "snort_rules_list": snort_rules_list,
        "sigma_rules_list": sigma_rules_list,
        "metadata": metadata,
    }
