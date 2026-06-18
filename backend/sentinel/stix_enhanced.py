"""
backend/sentinel/stix_enhanced.py
-----------------------------------
PhantomNet Sentinel Layer — Enriched STIX 2.1 Bundle Generator

Produces standards-compliant STIX 2.1 bundles that combine:
  * MITRE ATT&CK ExternalReference-enriched AttackPattern objects
  * Indicator objects derived from IOCs (IPs, domains, URLs, hashes)
  * Relationship objects that wire indicators → attack patterns
  * A PhantomNet Identity anchor object
  * Optional TLP marking definitions

Typical call flow (from sentinel_service.py):
    from sentinel.stix_enhanced import build_stix_bundle

    technique = map_signature("SSH_AUTH_FAILURE")   # from mitre_mapper
    iocs = [
        {"type": "ip",     "value": "192.168.1.100"},
        {"type": "domain", "value": "evil.c2.example"},
    ]
    bundle = build_stix_bundle(technique, iocs, src_ip="192.168.1.100")
    json_str = bundle.serialize(pretty=True)

Public API
----------
  build_stix_bundle(technique, iocs, src_ip, threat_score, tlp_level) -> stix2.Bundle
      Main entry point. Builds a full enriched STIX 2.1 bundle.

  build_attack_pattern(technique) -> stix2.AttackPattern
      Builds a MITRE ATT&CK-enriched AttackPattern from a technique dict.

  build_indicator(ioc, attack_pattern_id, threat_score, tlp_marking) -> stix2.Indicator | None
      Builds a STIX Indicator from a single IOC dict.

  build_relationship(source_ref, target_ref, rel_type) -> stix2.Relationship
      Wraps stix2.Relationship construction with PhantomNet defaults.

  PHANTOMNET_IDENTITY : stix2.Identity
      Singleton Identity object representing the PhantomNet Sentinel system.

Input Schemas
-------------
  technique dict (from mitre_mapper.map_signature / get_technique):
    {
      "technique_id":   str   # e.g. "T1110.001"
      "technique_name": str   # e.g. "Brute Force: Password Guessing"
      "tactic":         str   # e.g. "Credential Access"
      "tactic_id":      str   # e.g. "TA0006"     (optional)
      "description":    str   # human-readable
      "url":            str   # ATT&CK reference URL
      "severity":       str   # CRITICAL | HIGH | MEDIUM | LOW
    }

  IOC dict:
    {
      "type":  str  # "ip" | "domain" | "url" | "md5" | "sha256" | "email"
      "value": str  # The indicator value
    }

  TLP levels: "white" (default) | "green" | "amber" | "red"

STIX 2.1 Object Types Produced
-------------------------------
  identity        — PhantomNet Sentinel system anchor
  attack-pattern  — One per unique technique, with ATT&CK ExternalReferences
  indicator       — One per valid IOC
  relationship    — 'indicates' link: indicator → attack-pattern
  marking-definition — TLP colour as specified by caller
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import stix2

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# STIX 2.1 Pattern templates for each IOC type
# ---------------------------------------------------------------------------
_IOC_PATTERN_TEMPLATES: Dict[str, str] = {
    "ip":     "[ipv4-addr:value = '{value}']",
    "ipv4":   "[ipv4-addr:value = '{value}']",
    "ipv6":   "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url":    "[url:value = '{value}']",
    "md5":    "[file:hashes.MD5 = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "sha1":   "[file:hashes.'SHA-1' = '{value}']",
    "email":  "[email-addr:value = '{value}']",
}

# ---------------------------------------------------------------------------
# TLP Marking definitions (singleton references from stix2 library)
# ---------------------------------------------------------------------------
_TLP_MAP: Dict[str, stix2.MarkingDefinition] = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red":   stix2.TLP_RED,
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK Kill-Chain name
# ---------------------------------------------------------------------------
_MITRE_KILL_CHAIN = "mitre-attack"

# ---------------------------------------------------------------------------
# PhantomNet Sentinel Identity (singleton — always included in every bundle)
# ---------------------------------------------------------------------------
PHANTOMNET_IDENTITY: stix2.Identity = stix2.Identity(
    id="identity--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "phantomnet.sentinel")),
    name="PhantomNet Sentinel",
    identity_class="system",
    description=(
        "PhantomNet AI-Driven Active Defense Platform — Sentinel Layer. "
        "Automatically generates STIX 2.1 threat intelligence bundles from "
        "honeypot detections enriched with MITRE ATT&CK mappings."
    ),
    created=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    modified=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_utc() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(tz=timezone.utc)


def _tactic_to_phase_name(tactic: str) -> str:
    """
    Convert a MITRE ATT&CK tactic display name to its kill-chain phase slug.

    e.g. "Credential Access" -> "credential-access"
         "Command and Control" -> "command-and-control"
    """
    return tactic.lower().replace(" ", "-").replace("_", "-")


def _deterministic_stix_id(object_type: str, *seed_parts: str) -> str:
    """
    Generate a deterministic STIX ID for an object type + seed.

    Using deterministic IDs means the same technique / IOC always maps to the
    same STIX ID, enabling deduplication across multiple bundle generations.

    Args:
        object_type: STIX object type (e.g. "attack-pattern").
        *seed_parts: Strings concatenated to form the UUID seed.

    Returns:
        STIX-formatted ID string, e.g. "attack-pattern--<uuid5>".
    """
    seed = ":".join(seed_parts)
    uid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"phantomnet:{object_type}:{seed}"))
    return f"{object_type}--{uid}"


def _validate_ioc(ioc: Dict[str, Any]) -> bool:
    """
    Basic sanity-check for an IOC dict.

    Returns True if the IOC has a recognised type and a non-empty value.
    """
    ioc_type = str(ioc.get("type", "")).strip().lower()
    ioc_value = str(ioc.get("value", "")).strip()
    return bool(ioc_type and ioc_value and ioc_type in _IOC_PATTERN_TEMPLATES)


# ---------------------------------------------------------------------------
# Public builder functions
# ---------------------------------------------------------------------------

def build_attack_pattern(technique: Dict[str, Any]) -> stix2.AttackPattern:
    """
    Build a MITRE ATT&CK-enriched STIX 2.1 AttackPattern object.

    Args:
        technique: A technique dict as returned by mitre_mapper.map_signature()
                   or mitre_mapper.get_technique().  Required keys:
                   ``technique_id``, ``technique_name``, ``tactic``.
                   Optional: ``description``, ``url``, ``severity``.

    Returns:
        A ``stix2.AttackPattern`` with:
          - Deterministic STIX ID (reproducible across calls)
          - ATT&CK ExternalReference with technique ID and URL
          - KillChainPhase for the MITRE kill chain
          - Created-by-ref pointing to PHANTOMNET_IDENTITY

    Raises:
        ValueError: If ``technique_id`` or ``technique_name`` is missing.

    Example:
        >>> from sentinel.mitre_mapper import map_signature
        >>> t = map_signature("SSH_AUTH_FAILURE")
        >>> ap = build_attack_pattern(t)
        >>> ap.type
        'attack-pattern'
        >>> ap.external_references[0].external_id
        'T1110.001'
    """
    technique_id = technique.get("technique_id") or technique.get("id")
    technique_name = technique.get("technique_name") or technique.get("name")

    if not technique_id:
        raise ValueError("technique dict must contain 'technique_id' or 'id'")
    if not technique_name:
        raise ValueError("technique dict must contain 'technique_name' or 'name'")

    tactic = technique.get("tactic", "unknown")
    description = technique.get("description", f"MITRE ATT&CK technique {technique_id}: {technique_name}")
    url = technique.get("url") or technique.get("mitre_url") or (
        "https://attack.mitre.org/techniques/"
        + technique_id.replace(".", "/")
        + "/"
    )

    # Build the ATT&CK external reference (required for proper ATT&CK enrichment)
    att_ck_ref = stix2.ExternalReference(
        source_name="mitre-attack",
        external_id=technique_id,
        url=url,
    )

    # Kill-chain phase derived from the tactic name
    kill_chain_phase = stix2.KillChainPhase(
        kill_chain_name=_MITRE_KILL_CHAIN,
        phase_name=_tactic_to_phase_name(tactic),
    )

    now = _now_utc()

    return stix2.AttackPattern(
        id=_deterministic_stix_id("attack-pattern", technique_id),
        created_by_ref=PHANTOMNET_IDENTITY.id,
        created=now,
        modified=now,
        name=technique_name,
        description=description,
        kill_chain_phases=[kill_chain_phase],
        external_references=[att_ck_ref],
    )


def build_indicator(
    ioc: Dict[str, Any],
    attack_pattern_id: str,
    threat_score: float = 0.0,
    tlp_marking: Optional[stix2.MarkingDefinition] = None,
    valid_from: Optional[datetime] = None,
) -> Optional[stix2.Indicator]:
    """
    Build a STIX 2.1 Indicator from a single IOC dict.

    Args:
        ioc:               Dict with ``type`` and ``value`` keys.
        attack_pattern_id: STIX ID of the AttackPattern this indicator relates to.
                           Used to populate the indicator description.
        threat_score:      ML threat confidence score (0–100). Reflected in the
                           indicator name for analyst context.
        tlp_marking:       TLP marking definition to attach. Defaults to TLP:WHITE.
        valid_from:        UTC datetime for the indicator's validity start.
                           Defaults to now.

    Returns:
        A ``stix2.Indicator`` or ``None`` if the IOC type is unrecognised or
        the value is empty.

    IOC types supported:
        ip / ipv4 / ipv6 / domain / url / md5 / sha256 / sha1 / email

    Example:
        >>> ioc = {"type": "ip", "value": "192.168.1.100"}
        >>> ind = build_indicator(ioc, "attack-pattern--abc", threat_score=87.5)
        >>> ind.type
        'indicator'
        >>> '[ipv4-addr:value' in ind.pattern
        True
    """
    if not _validate_ioc(ioc):
        logger.warning("Skipping invalid or unrecognised IOC: %s", ioc)
        return None

    ioc_type = str(ioc["type"]).strip().lower()
    ioc_value = str(ioc["value"]).strip()
    pattern_template = _IOC_PATTERN_TEMPLATES[ioc_type]
    pattern = pattern_template.format(value=ioc_value)

    marking = tlp_marking or stix2.TLP_WHITE
    now = _now_utc()
    valid_from_ts = valid_from or now

    # Indicator name: human-readable, includes threat score for analyst context
    score_tag = f" [score: {threat_score:.0f}]" if threat_score > 0 else ""
    indicator_name = f"PhantomNet: {ioc_type.upper()} IOC — {ioc_value}{score_tag}"

    return stix2.Indicator(
        id=_deterministic_stix_id("indicator", ioc_type, ioc_value, attack_pattern_id),
        created_by_ref=PHANTOMNET_IDENTITY.id,
        created=now,
        modified=now,
        name=indicator_name,
        description=(
            f"IOC of type '{ioc_type}' with value '{ioc_value}' detected by "
            f"PhantomNet Sentinel. Associated ATT&CK pattern: {attack_pattern_id}. "
            f"Threat score: {threat_score:.1f}/100."
        ),
        indicator_types=["malicious-activity"],
        pattern=pattern,
        pattern_type="stix",
        valid_from=valid_from_ts,
        object_marking_refs=[marking.id],
    )


def build_relationship(
    source_ref: str,
    target_ref: str,
    relationship_type: str = "indicates",
) -> stix2.Relationship:
    """
    Build a STIX 2.1 Relationship object.

    Args:
        source_ref:        STIX ID of the source object (typically an Indicator).
        target_ref:        STIX ID of the target object (typically an AttackPattern).
        relationship_type: STIX relationship type string. Default: "indicates".

    Returns:
        A ``stix2.Relationship`` with a deterministic STIX ID.

    Example:
        >>> rel = build_relationship(ind.id, ap.id)
        >>> rel.relationship_type
        'indicates'
        >>> rel.source_ref == ind.id
        True
    """
    now = _now_utc()
    return stix2.Relationship(
        id=_deterministic_stix_id("relationship", relationship_type, source_ref, target_ref),
        created_by_ref=PHANTOMNET_IDENTITY.id,
        created=now,
        modified=now,
        relationship_type=relationship_type,
        source_ref=source_ref,
        target_ref=target_ref,
    )


def build_stix_bundle(
    technique: Dict[str, Any],
    iocs: Optional[List[Dict[str, Any]]] = None,
    src_ip: Optional[str] = None,
    threat_score: float = 0.0,
    tlp_level: str = "white",
    valid_from: Optional[datetime] = None,
) -> stix2.Bundle:
    """
    Build a complete, enriched STIX 2.1 bundle from a technique + IOC list.

    This is the primary entry point for the Sentinel pipeline.  It:
      1. Resolves the TLP marking definition.
      2. Builds an ATT&CK-enriched AttackPattern.
      3. Automatically adds ``src_ip`` as an IP IOC if provided.
      4. Builds an Indicator for each valid IOC.
      5. Creates 'indicates' Relationship objects linking each Indicator
         to the AttackPattern.
      6. Assembles everything (plus the PhantomNet Identity and TLP marking)
         into a STIX Bundle.

    Args:
        technique:    Technique dict from mitre_mapper.map_signature() or
                      mitre_mapper.get_technique().
        iocs:         List of IOC dicts ``{"type": str, "value": str}``.
                      Supported types: ip, ipv4, ipv6, domain, url, md5,
                      sha256, sha1, email.
        src_ip:       Source IP from the detected event. Automatically
                      added as an IP-type IOC if not already in ``iocs``.
        threat_score: ML threat confidence score (0.0–100.0).
        tlp_level:    TLP colour ("white", "green", "amber", "red").
                      Default: "white".
        valid_from:   Validity start for all Indicators. Defaults to now (UTC).

    Returns:
        A ``stix2.Bundle`` containing:
          - 1 × Identity  (PhantomNet Sentinel)
          - 1 × MarkingDefinition (TLP as specified)
          - 1 × AttackPattern (enriched with ATT&CK ExternalReference)
          - N × Indicator  (one per valid IOC)
          - N × Relationship (one 'indicates' link per Indicator)

    Raises:
        ValueError: If ``technique`` is missing required keys.

    Example:
        >>> from sentinel.mitre_mapper import map_signature
        >>> technique = map_signature("SSH_AUTH_FAILURE")
        >>> iocs = [{"type": "ip", "value": "10.0.0.5"}]
        >>> bundle = build_stix_bundle(technique, iocs, src_ip="10.0.0.5",
        ...                           threat_score=87.5, tlp_level="green")
        >>> bundle.type
        'bundle'
        >>> len(bundle.objects) >= 4
        True
    """
    # ── 1. Resolve TLP marking ─────────────────────────────────────────────
    tlp_level_clean = str(tlp_level).strip().lower()
    tlp_marking = _TLP_MAP.get(tlp_level_clean, stix2.TLP_WHITE)

    # ── 2. Build ATT&CK-enriched AttackPattern ─────────────────────────────
    attack_pattern = build_attack_pattern(technique)

    # ── 3. Normalise IOC list; inject src_ip if provided ──────────────────
    ioc_list: List[Dict[str, Any]] = list(iocs) if iocs else []

    if src_ip:
        src_ip_ioc = {"type": "ip", "value": src_ip}
        # Only add if not already present with the same value
        existing_values = {i.get("value") for i in ioc_list}
        if src_ip not in existing_values:
            ioc_list.insert(0, src_ip_ioc)

    # ── 4. Build Indicator + Relationship for each valid IOC ───────────────
    indicators: List[stix2.Indicator] = []
    relationships: List[stix2.Relationship] = []

    for ioc in ioc_list:
        indicator = build_indicator(
            ioc=ioc,
            attack_pattern_id=attack_pattern.id,
            threat_score=threat_score,
            tlp_marking=tlp_marking,
            valid_from=valid_from,
        )
        if indicator is None:
            continue  # skip invalid IOCs silently (already logged)

        relationship = build_relationship(
            source_ref=indicator.id,
            target_ref=attack_pattern.id,
            relationship_type="indicates",
        )
        indicators.append(indicator)
        relationships.append(relationship)

    # ── 5. Assemble bundle ────────────────────────────────────────────────
    # Object order: Identity → MarkingDefinition → AttackPattern →
    #               Indicators → Relationships
    bundle_objects: List[Any] = (
        [PHANTOMNET_IDENTITY, tlp_marking, attack_pattern]
        + indicators
        + relationships
    )

    bundle = stix2.Bundle(
        objects=bundle_objects,
        allow_custom=False,
    )

    logger.info(
        "[stix_enhanced] Bundle %s built: technique=%s iocs=%d objects=%d tlp=%s",
        bundle.id,
        technique.get("technique_id") or technique.get("id"),
        len(indicators),
        len(bundle.objects),
        tlp_level_clean,
    )

    return bundle


def bundle_to_dict(bundle: stix2.Bundle) -> Dict[str, Any]:
    """
    Serialize a STIX Bundle to a Python dict (JSON-safe).

    Args:
        bundle: A ``stix2.Bundle`` object.

    Returns:
        A plain Python dict representation of the bundle.

    Example:
        >>> d = bundle_to_dict(bundle)
        >>> d["type"]
        'bundle'
        >>> isinstance(d["objects"], list)
        True
    """
    return json.loads(bundle.serialize())


def bundle_to_json(bundle: stix2.Bundle, pretty: bool = True) -> str:
    """
    Serialize a STIX Bundle to a JSON string.

    Args:
        bundle: A ``stix2.Bundle`` object.
        pretty: If True (default), format with 2-space indentation.

    Returns:
        A JSON string representing the STIX bundle.

    Example:
        >>> json_str = bundle_to_json(bundle)
        >>> '"type": "bundle"' in json_str
        True
    """
    return bundle.serialize(pretty=pretty)
