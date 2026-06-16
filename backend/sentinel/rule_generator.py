"""
backend/sentinel/rule_generator.py
------------------------------------
PhantomNet Sentinel Layer — Snort Rule Generator

Generates Snort IDS rules from ATT&CK technique data captured by the
Sentinel pipeline. Rules are produced by sentinel_service.py and can be
exported from the Sentinel Dashboard.

Public API
----------
  generate_snort_rule(src_ip, dst_port, protocol, attack_desc,
                      technique_id, sid) -> str
      Generates a single formatted Snort rule string.
      Raises ValueError on invalid inputs.

  validate_ip(ip_str) -> bool
      Returns True for valid IPv4, CIDR, or Snort keywords (any, $HOME_NET).

  validate_port(port) -> bool
      Returns True for valid port number (0-65535) or 'any'.

  SNORT_RULE_TEMPLATE : str
      The raw template string used for rule generation.
"""

import ipaddress
import threading
import typing

# Thread-safe SID tracking
_sid_lock = threading.Lock()
_NEXT_SID = 1000001


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
    """Validate if the string is a valid IP address or allowed variable/keyword."""
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
        return False


def validate_port(port: typing.Union[int, str]) -> bool:
    """Validate if the port is a valid port number or 'any'."""
    if isinstance(port, str) and port.lower() == "any":
        return True
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except ValueError:
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

