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
import typing

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
    sid: int,
) -> str:
    """
    Generates a Snort rule string based on the provided parameters.

    Args:
        src_ip:       Source IP address (e.g., '192.168.1.1', 'any', '$EXTERNAL_NET')
        dst_port:     Destination port (e.g., 22, 80, 'any')
        protocol:     Network protocol (e.g., 'tcp', 'udp', 'icmp')
        attack_desc:  Description of the attack for the 'msg' field
        technique_id: MITRE ATT&CK technique ID for the 'reference' field
        sid:          Snort rule ID

    Returns:
        A formatted Snort rule string.

    Raises:
        ValueError: If input parameters are invalid.
    """
    if not validate_ip(src_ip):
        raise ValueError(f"Invalid source IP address: {src_ip}")

    if not validate_port(dst_port):
        raise ValueError(f"Invalid destination port: {dst_port}")

    protocol = protocol.lower()
    if protocol not in ("tcp", "udp", "icmp", "ip"):
        raise ValueError(f"Unsupported protocol: {protocol}")

    rule = SNORT_RULE_TEMPLATE.format(
        protocol=protocol,
        src_ip=src_ip,
        dst_port=dst_port,
        attack_desc=attack_desc,
        technique_id=technique_id,
        sid=sid,
    )

    return rule
