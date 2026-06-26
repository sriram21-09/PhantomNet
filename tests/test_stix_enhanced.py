"""
tests/test_stix_enhanced.py
----------------------------
Comprehensive tests for backend/sentinel/stix_enhanced.py covering:

  1. ATT&CK ExternalReferences in AttackPattern objects
  2. Correct MITRE ATT&CK technique URLs
  3. Relationship objects linking indicators to attack patterns
  4. STIX 2.1 schema compliance (type, spec_version, id fields)
  5. Multiple IOCs in a single bundle
  6. Different attack types (SSH, HTTP, FTP, SMTP)
  7. Bundle timestamp and metadata fields
  8. IOC pattern correctness for all supported types
  9. TLP marking definitions
  10. Edge cases and error handling

All tests work against:
  backend/sentinel/stix_enhanced.py
  (resolved via tests/conftest.py which adds backend/ to sys.path)
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

import pytest
import stix2

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "backend")
for _p in (_ROOT, _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from sentinel.stix_enhanced import (
    PHANTOMNET_IDENTITY,
    _IOC_PATTERN_TEMPLATES,
    _TLP_MAP,
    _deterministic_stix_id,
    _tactic_to_phase_name,
    _validate_ioc,
    build_attack_pattern,
    build_indicator,
    build_relationship,
    build_stix_bundle,
    bundle_to_dict,
    bundle_to_json,
)


# ===========================================================================
# Shared fixtures
# ===========================================================================

@pytest.fixture
def ssh_technique():
    """SSH brute-force technique dict (T1110.001)."""
    return {
        "technique_id":   "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic":         "Credential Access",
        "tactic_id":      "TA0006",
        "description":    "Adversary systematically guesses SSH passwords.",
        "url":            "https://attack.mitre.org/techniques/T1110/001/",
        "severity":       "CRITICAL",
    }


@pytest.fixture
def http_technique():
    """HTTP exploit technique dict (T1190)."""
    return {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "description":    "Adversary exploits an internet-facing HTTP service.",
        "url":            "https://attack.mitre.org/techniques/T1190/",
        "severity":       "HIGH",
    }


@pytest.fixture
def ftp_technique():
    """FTP brute-force technique dict (T1110.003)."""
    return {
        "technique_id":   "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "tactic":         "Credential Access",
        "description":    "Low-and-slow password spraying against FTP service.",
        "severity":       "HIGH",
    }


@pytest.fixture
def smtp_technique():
    """SMTP phishing technique dict (T1566.001)."""
    return {
        "technique_id":   "T1566.001",
        "technique_name": "Phishing: Spearphishing Attachment",
        "tactic":         "Initial Access",
        "description":    "Adversary sends spearphishing e-mails with malicious attachments.",
        "severity":       "CRITICAL",
    }


@pytest.fixture
def c2_technique():
    """C2/exfiltration technique dict (T1041)."""
    return {
        "technique_id":   "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic":         "Exfiltration",
        "description":    "Data exfiltrated over existing C2 channel.",
        "severity":       "CRITICAL",
    }


@pytest.fixture
def single_ip_ioc():
    return [{"type": "ip", "value": "192.168.1.100"}]


@pytest.fixture
def multi_ioc_list():
    return [
        {"type": "ip",     "value": "185.220.101.42"},
        {"type": "ip",     "value": "45.33.32.156"},
        {"type": "domain", "value": "evil.c2.example.com"},
        {"type": "url",    "value": "http://malware.example.com/payload.exe"},
        {"type": "md5",    "value": "d41d8cd98f00b204e9800998ecf8427e"},
        {"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    ]


@pytest.fixture
def ssh_bundle(ssh_technique, single_ip_ioc):
    return build_stix_bundle(ssh_technique, single_ip_ioc, src_ip="192.168.1.100",
                             threat_score=87.5, tlp_level="green")


@pytest.fixture
def ssh_bundle_dict(ssh_bundle):
    return bundle_to_dict(ssh_bundle)


# ===========================================================================
# 1. BUNDLE STRUCTURE & STIX 2.1 SCHEMA COMPLIANCE
# ===========================================================================

class TestBundleStructure:
    """Verify the bundle type, spec_version, id, and object count."""

    def test_bundle_type_is_bundle(self, ssh_bundle):
        assert ssh_bundle.type == "bundle"

    def test_bundle_has_spec_version(self, ssh_bundle):
        """In stix2 v3, spec_version appears on individual STIX objects,
        not the bundle root. Verify at least one object carries it."""
        d = bundle_to_dict(ssh_bundle)
        # spec_version lives on each STIX object, not the bundle envelope
        objects_with_spec = [
            obj for obj in d["objects"]
            if obj.get("spec_version") == "2.1"
        ]
        assert len(objects_with_spec) >= 1, (
            "At least one STIX object must carry spec_version=2.1"
        )

    def test_bundle_has_id_field(self, ssh_bundle):
        assert ssh_bundle.id.startswith("bundle--")

    def test_bundle_id_is_valid_uuid(self, ssh_bundle):
        uid = ssh_bundle.id.replace("bundle--", "")
        # Should parse as valid UUID
        uuid.UUID(uid)

    def test_bundle_has_objects_list(self, ssh_bundle):
        assert hasattr(ssh_bundle, "objects")
        assert isinstance(ssh_bundle.objects, (list, tuple))

    def test_bundle_minimum_4_objects(self, ssh_bundle, single_ip_ioc):
        # identity + TLP marking + attack-pattern + ≥1 indicator
        assert len(ssh_bundle.objects) >= 4

    def test_bundle_contains_identity(self, ssh_bundle):
        types = [o.type for o in ssh_bundle.objects]
        assert "identity" in types

    def test_bundle_contains_marking_definition(self, ssh_bundle):
        types = [o.type for o in ssh_bundle.objects]
        assert "marking-definition" in types

    def test_bundle_contains_attack_pattern(self, ssh_bundle):
        types = [o.type for o in ssh_bundle.objects]
        assert "attack-pattern" in types

    def test_bundle_contains_indicator(self, ssh_bundle):
        types = [o.type for o in ssh_bundle.objects]
        assert "indicator" in types

    def test_bundle_contains_relationship(self, ssh_bundle):
        types = [o.type for o in ssh_bundle.objects]
        assert "relationship" in types

    def test_bundle_serializes_to_valid_json(self, ssh_bundle):
        json_str = bundle_to_json(ssh_bundle)
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"

    def test_bundle_dict_structure(self, ssh_bundle_dict):
        assert "type" in ssh_bundle_dict
        assert "id" in ssh_bundle_dict
        assert "objects" in ssh_bundle_dict
        assert isinstance(ssh_bundle_dict["objects"], list)
        # spec_version is on individual STIX objects in stix2 v3
        assert any(
            obj.get("spec_version") == "2.1"
            for obj in ssh_bundle_dict["objects"]
        ), "At least one object must have spec_version=2.1"

    @pytest.mark.parametrize("stix_obj_type", [
        "identity", "marking-definition", "attack-pattern", "indicator", "relationship",
    ])
    def test_each_object_has_required_stix_fields(self, ssh_bundle, stix_obj_type):
        """Every STIX object must have type, id, created, modified."""
        objects_of_type = [o for o in ssh_bundle.objects if o.type == stix_obj_type]
        assert len(objects_of_type) >= 1, f"No {stix_obj_type} in bundle"
        for obj in objects_of_type:
            d = json.loads(obj.serialize())
            assert "type" in d
            assert "id" in d
            if stix_obj_type not in ("marking-definition",):
                assert "created" in d
                assert "modified" in d


# ===========================================================================
# 2. ATT&CK EXTERNAL REFERENCES
# ===========================================================================

class TestATTCKExternalReferences:
    """
    Verify AttackPattern objects carry the correct ATT&CK ExternalReferences:
      - source_name == "mitre-attack"
      - external_id == the technique ID
      - url points to attack.mitre.org
    """

    def test_attack_pattern_has_external_references(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert len(ap.external_references) >= 1

    def test_external_reference_source_name_is_mitre_attack(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        ext_ref = ap.external_references[0]
        assert ext_ref.source_name == "mitre-attack"

    def test_external_reference_has_correct_technique_id(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        ext_ref = ap.external_references[0]
        assert ext_ref.external_id == "T1110.001"

    def test_external_reference_url_points_to_mitre(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        ext_ref = ap.external_references[0]
        assert "attack.mitre.org" in ext_ref.url

    def test_external_reference_url_contains_technique_id_path(self, ssh_technique):
        """T1110.001 → URL must contain T1110/001/"""
        ap = build_attack_pattern(ssh_technique)
        ext_ref = ap.external_references[0]
        assert "T1110" in ext_ref.url
        assert "001" in ext_ref.url

    def test_external_reference_in_bundle(self, ssh_bundle):
        """ATT&CK ExternalReference must survive bundle assembly."""
        aps = [o for o in ssh_bundle.objects if o.type == "attack-pattern"]
        assert len(aps) == 1
        ext_ref = aps[0].external_references[0]
        assert ext_ref.source_name == "mitre-attack"
        assert ext_ref.external_id == "T1110.001"

    @pytest.mark.parametrize("technique_id,expected_path", [
        ("T1190",     "T1190/"),
        ("T1110.001", "T1110/001/"),
        ("T1566.001", "T1566/001/"),
        ("T1041",     "T1041/"),
        ("T1595.001", "T1595/001/"),
    ])
    def test_mitre_url_path_format(self, technique_id, expected_path):
        """Technique ID dots must become URL path separators."""
        technique = {
            "technique_id": technique_id,
            "technique_name": f"Technique {technique_id}",
            "tactic": "Credential Access",
        }
        ap = build_attack_pattern(technique)
        url = ap.external_references[0].url
        assert expected_path in url, \
            f"Expected '{expected_path}' in URL '{url}' for technique {technique_id}"

    def test_caller_provided_url_is_used(self):
        """If a URL is provided in the technique dict, it must be used as-is."""
        technique = {
            "technique_id":   "T1110",
            "technique_name": "Brute Force",
            "tactic":         "Credential Access",
            "url": "https://custom.example.com/T1110/",
        }
        ap = build_attack_pattern(technique)
        assert ap.external_references[0].url == "https://custom.example.com/T1110/"

    def test_url_auto_generated_when_not_provided(self):
        """When no URL in technique dict, URL is auto-generated from technique_id."""
        technique = {
            "technique_id":   "T1046",
            "technique_name": "Network Service Discovery",
            "tactic":         "Discovery",
        }
        ap = build_attack_pattern(technique)
        url = ap.external_references[0].url
        assert "attack.mitre.org" in url
        assert "T1046" in url


# ===========================================================================
# 3. CORRECT MITRE ATT&CK TECHNIQUE URLS
# ===========================================================================

class TestATTCKTechniqueURLs:
    """Verify the full URL format is correct for all attack types tested."""

    def test_ssh_brute_force_url(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.external_references[0].url == "https://attack.mitre.org/techniques/T1110/001/"

    def test_http_exploit_url(self, http_technique):
        ap = build_attack_pattern(http_technique)
        assert ap.external_references[0].url == "https://attack.mitre.org/techniques/T1190/"

    def test_ftp_brute_force_url(self, ftp_technique):
        ap = build_attack_pattern(ftp_technique)
        assert ap.external_references[0].url == "https://attack.mitre.org/techniques/T1110/003/"

    def test_smtp_phishing_url(self, smtp_technique):
        ap = build_attack_pattern(smtp_technique)
        assert ap.external_references[0].url == "https://attack.mitre.org/techniques/T1566/001/"

    def test_c2_exfil_url(self, c2_technique):
        ap = build_attack_pattern(c2_technique)
        assert ap.external_references[0].url == "https://attack.mitre.org/techniques/T1041/"

    def test_url_is_https(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.external_references[0].url.startswith("https://")

    def test_url_ends_with_slash(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.external_references[0].url.endswith("/")


# ===========================================================================
# 4. ATTACK PATTERN OBJECT PROPERTIES
# ===========================================================================

class TestAttackPatternObject:
    """Verify AttackPattern fields map correctly from the technique dict."""

    def test_attack_pattern_type(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.type == "attack-pattern"

    def test_attack_pattern_id_format(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.id.startswith("attack-pattern--")

    def test_attack_pattern_id_is_deterministic(self, ssh_technique):
        """Same technique always produces the same STIX ID."""
        ap1 = build_attack_pattern(ssh_technique)
        ap2 = build_attack_pattern(ssh_technique)
        assert ap1.id == ap2.id

    def test_attack_pattern_name(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.name == "Brute Force: Password Guessing"

    def test_attack_pattern_description(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert "SSH" in ap.description or "brute" in ap.description.lower() \
               or "password" in ap.description.lower()

    def test_attack_pattern_created_by_phantomnet(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.created_by_ref == PHANTOMNET_IDENTITY.id

    def test_attack_pattern_has_kill_chain_phases(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert len(ap.kill_chain_phases) >= 1

    def test_attack_pattern_kill_chain_name(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        kcp = ap.kill_chain_phases[0]
        assert kcp.kill_chain_name == "mitre-attack"

    def test_attack_pattern_tactic_phase_name(self, ssh_technique):
        """Credential Access → credential-access"""
        ap = build_attack_pattern(ssh_technique)
        kcp = ap.kill_chain_phases[0]
        assert kcp.phase_name == "credential-access"

    @pytest.mark.parametrize("tactic,expected_phase", [
        ("Credential Access",    "credential-access"),
        ("Initial Access",       "initial-access"),
        ("Command and Control",  "command-and-control"),
        ("Lateral Movement",     "lateral-movement"),
        ("Exfiltration",         "exfiltration"),
        ("Discovery",            "discovery"),
        ("Reconnaissance",       "reconnaissance"),
        ("Defense Evasion",      "defense-evasion"),
    ])
    def test_tactic_to_phase_name_conversion(self, tactic, expected_phase):
        result = _tactic_to_phase_name(tactic)
        assert result == expected_phase

    def test_attack_pattern_missing_technique_id_raises(self):
        with pytest.raises(ValueError, match="technique_id"):
            build_attack_pattern({"technique_name": "Brute Force", "tactic": "Credential Access"})

    def test_attack_pattern_missing_name_raises(self):
        with pytest.raises(ValueError, match="technique_name"):
            build_attack_pattern({"technique_id": "T1110", "tactic": "Credential Access"})

    def test_attack_pattern_id_alias_support(self):
        """'id' key is accepted as alias for 'technique_id'."""
        ap = build_attack_pattern({"id": "T1046", "name": "Network Service Discovery",
                                   "tactic": "Discovery"})
        assert ap.type == "attack-pattern"
        assert ap.external_references[0].external_id == "T1046"

    @pytest.mark.parametrize("fixture_name", [
        "ssh_technique", "http_technique", "ftp_technique", "smtp_technique", "c2_technique",
    ])
    def test_all_attack_types_build_without_error(self, request, fixture_name):
        technique = request.getfixturevalue(fixture_name)
        ap = build_attack_pattern(technique)
        assert ap.type == "attack-pattern"


# ===========================================================================
# 5. RELATIONSHIP OBJECTS
# ===========================================================================

class TestRelationshipObjects:
    """Verify relationship objects correctly link indicators to attack patterns."""

    @pytest.fixture
    def indicator_and_ap(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        ioc = {"type": "ip", "value": "10.0.0.1"}
        ind = build_indicator(ioc, ap.id, threat_score=80.0)
        return ind, ap

    def test_relationship_type_is_relationship(self, indicator_and_ap):
        ind, ap = indicator_and_ap
        rel = build_relationship(ind.id, ap.id)
        assert rel.type == "relationship"

    def test_relationship_type_is_indicates(self, indicator_and_ap):
        ind, ap = indicator_and_ap
        rel = build_relationship(ind.id, ap.id)
        assert rel.relationship_type == "indicates"

    def test_relationship_source_ref_is_indicator(self, indicator_and_ap):
        ind, ap = indicator_and_ap
        rel = build_relationship(ind.id, ap.id)
        assert rel.source_ref == ind.id

    def test_relationship_target_ref_is_attack_pattern(self, indicator_and_ap):
        ind, ap = indicator_and_ap
        rel = build_relationship(ind.id, ap.id)
        assert rel.target_ref == ap.id

    def test_relationship_id_starts_with_relationship(self, indicator_and_ap):
        ind, ap = indicator_and_ap
        rel = build_relationship(ind.id, ap.id)
        assert rel.id.startswith("relationship--")

    def test_relationship_id_is_deterministic(self, indicator_and_ap):
        """Same source/target always produces same relationship ID."""
        ind, ap = indicator_and_ap
        rel1 = build_relationship(ind.id, ap.id)
        rel2 = build_relationship(ind.id, ap.id)
        assert rel1.id == rel2.id

    def test_relationship_created_by_phantomnet(self, indicator_and_ap):
        ind, ap = indicator_and_ap
        rel = build_relationship(ind.id, ap.id)
        assert rel.created_by_ref == PHANTOMNET_IDENTITY.id

    def test_relationship_custom_type(self, indicator_and_ap):
        ind, ap = indicator_and_ap
        rel = build_relationship(ind.id, ap.id, relationship_type="related-to")
        assert rel.relationship_type == "related-to"

    def test_bundle_has_relationship_per_indicator(self, ssh_bundle):
        """Each indicator must have exactly one 'indicates' relationship."""
        indicators    = [o for o in ssh_bundle.objects if o.type == "indicator"]
        relationships = [o for o in ssh_bundle.objects if o.type == "relationship"]
        assert len(relationships) == len(indicators)

    def test_relationship_source_refs_match_indicator_ids(self, ssh_bundle):
        """All relationship source_refs point to indicator objects in the bundle."""
        indicator_ids = {o.id for o in ssh_bundle.objects if o.type == "indicator"}
        relationships = [o for o in ssh_bundle.objects if o.type == "relationship"]
        for rel in relationships:
            assert rel.source_ref in indicator_ids, \
                f"Relationship source_ref {rel.source_ref} not in indicator IDs"

    def test_relationship_target_refs_match_attack_pattern_ids(self, ssh_bundle):
        """All relationship target_refs point to the attack-pattern in the bundle."""
        ap_ids = {o.id for o in ssh_bundle.objects if o.type == "attack-pattern"}
        relationships = [o for o in ssh_bundle.objects if o.type == "relationship"]
        for rel in relationships:
            assert rel.target_ref in ap_ids, \
                f"Relationship target_ref {rel.target_ref} not in attack-pattern IDs"


# ===========================================================================
# 6. INDICATOR OBJECTS & IOC PATTERNS
# ===========================================================================

class TestIndicatorObjects:
    """Verify Indicator objects carry correct STIX patterns for each IOC type."""

    @pytest.fixture
    def ap_id(self, ssh_technique):
        return build_attack_pattern(ssh_technique).id

    def test_indicator_type(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.2.3.4"}, ap_id)
        assert ind.type == "indicator"

    def test_indicator_id_format(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.2.3.4"}, ap_id)
        assert ind.id.startswith("indicator--")

    def test_indicator_id_is_deterministic(self, ap_id):
        ind1 = build_indicator({"type": "ip", "value": "1.2.3.4"}, ap_id)
        ind2 = build_indicator({"type": "ip", "value": "1.2.3.4"}, ap_id)
        assert ind1.id == ind2.id

    def test_indicator_pattern_type_is_stix(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.2.3.4"}, ap_id)
        assert ind.pattern_type == "stix"

    # ── IP pattern ─────────────────────────────────────────────────────────
    def test_ip_indicator_pattern(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "192.168.1.100"}, ap_id)
        assert "[ipv4-addr:value = '192.168.1.100']" in ind.pattern

    def test_ipv4_indicator_pattern(self, ap_id):
        ind = build_indicator({"type": "ipv4", "value": "10.0.0.1"}, ap_id)
        assert "[ipv4-addr:value = '10.0.0.1']" in ind.pattern

    def test_ipv6_indicator_pattern(self, ap_id):
        ind = build_indicator({"type": "ipv6", "value": "::1"}, ap_id)
        assert "[ipv6-addr:value = '::1']" in ind.pattern

    # ── Domain pattern ──────────────────────────────────────────────────────
    def test_domain_indicator_pattern(self, ap_id):
        ind = build_indicator({"type": "domain", "value": "evil.c2.example.com"}, ap_id)
        assert "[domain-name:value = 'evil.c2.example.com']" in ind.pattern

    # ── URL pattern ─────────────────────────────────────────────────────────
    def test_url_indicator_pattern(self, ap_id):
        ind = build_indicator({"type": "url", "value": "http://bad.example.com/shell"}, ap_id)
        assert "[url:value = 'http://bad.example.com/shell']" in ind.pattern

    # ── Hash patterns ───────────────────────────────────────────────────────
    def test_md5_indicator_pattern(self, ap_id):
        ind = build_indicator(
            {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}, ap_id)
        assert "file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e'" in ind.pattern

    def test_sha256_indicator_pattern(self, ap_id):
        ind = build_indicator(
            {"type": "sha256",
             "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            ap_id)
        assert "SHA-256" in ind.pattern

    def test_sha1_indicator_pattern(self, ap_id):
        ind = build_indicator(
            {"type": "sha1", "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}, ap_id)
        assert "SHA-1" in ind.pattern

    # ── Email pattern ───────────────────────────────────────────────────────
    def test_email_indicator_pattern(self, ap_id):
        ind = build_indicator({"type": "email", "value": "phisher@evil.example"}, ap_id)
        assert "[email-addr:value = 'phisher@evil.example']" in ind.pattern

    # ── Threat score ────────────────────────────────────────────────────────
    def test_threat_score_appears_in_indicator_name(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap_id, threat_score=93.7)
        assert "93" in ind.name or "score" in ind.name.lower()

    def test_zero_threat_score_no_score_tag(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap_id, threat_score=0.0)
        assert "score" not in ind.name.lower()

    # ── Invalid IOC ─────────────────────────────────────────────────────────
    def test_invalid_ioc_type_returns_none(self, ap_id):
        result = build_indicator({"type": "xml", "value": "anything"}, ap_id)
        assert result is None

    def test_empty_ioc_value_returns_none(self, ap_id):
        result = build_indicator({"type": "ip", "value": ""}, ap_id)
        assert result is None

    def test_missing_ioc_type_returns_none(self, ap_id):
        result = build_indicator({"value": "1.1.1.1"}, ap_id)
        assert result is None

    # ── TLP marking ─────────────────────────────────────────────────────────
    def test_indicator_has_object_marking_refs(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap_id,
                              tlp_marking=stix2.TLP_GREEN)
        assert len(ind.object_marking_refs) >= 1

    def test_indicator_tlp_white_by_default(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap_id)
        assert stix2.TLP_WHITE.id in ind.object_marking_refs

    def test_indicator_tlp_red_applied(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap_id,
                              tlp_marking=stix2.TLP_RED)
        assert stix2.TLP_RED.id in ind.object_marking_refs

    def test_indicator_created_by_phantomnet(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap_id)
        assert ind.created_by_ref == PHANTOMNET_IDENTITY.id

    def test_indicator_types_contains_malicious_activity(self, ap_id):
        ind = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap_id)
        assert "malicious-activity" in ind.indicator_types


# ===========================================================================
# 7. MULTIPLE IOCs IN A SINGLE BUNDLE
# ===========================================================================

class TestMultipleIOCsInBundle:
    """Verify bundles with multiple IOCs produce correct indicator/relationship counts."""

    def test_6_iocs_produce_6_indicators(self, ssh_technique, multi_ioc_list):
        bundle = build_stix_bundle(ssh_technique, multi_ioc_list)
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        assert len(indicators) == 6

    def test_6_iocs_produce_6_relationships(self, ssh_technique, multi_ioc_list):
        bundle = build_stix_bundle(ssh_technique, multi_ioc_list)
        relationships = [o for o in bundle.objects if o.type == "relationship"]
        assert len(relationships) == 6

    def test_total_object_count_is_correct(self, ssh_technique, multi_ioc_list):
        # identity(1) + TLP(1) + attack-pattern(1) + indicators(6) + relationships(6) = 15
        bundle = build_stix_bundle(ssh_technique, multi_ioc_list)
        assert len(bundle.objects) == 15

    def test_all_ioc_types_represented(self, ssh_technique, multi_ioc_list):
        bundle = build_stix_bundle(ssh_technique, multi_ioc_list)
        patterns = " ".join(o.pattern for o in bundle.objects if o.type == "indicator")
        assert "ipv4-addr" in patterns
        assert "domain-name" in patterns
        assert "url" in patterns
        assert "MD5" in patterns
        assert "SHA-256" in patterns

    def test_src_ip_auto_added_when_not_in_ioc_list(self, ssh_technique):
        iocs = [{"type": "domain", "value": "evil.example.com"}]
        bundle = build_stix_bundle(ssh_technique, iocs, src_ip="10.0.0.99")
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        # Should have 2: domain + auto-added src_ip
        assert len(indicators) == 2
        patterns = " ".join(o.pattern for o in indicators)
        assert "10.0.0.99" in patterns

    def test_src_ip_not_duplicated_if_already_in_ioc_list(self, ssh_technique):
        iocs = [{"type": "ip", "value": "10.0.0.99"}]
        bundle = build_stix_bundle(ssh_technique, iocs, src_ip="10.0.0.99")
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        # Should be 1, not 2 (no duplicate)
        assert len(indicators) == 1

    def test_invalid_iocs_skipped(self, ssh_technique):
        iocs = [
            {"type": "ip", "value": "1.1.1.1"},
            {"type": "invalid_type", "value": "garbage"},
            {"type": "ip", "value": ""},
            {"type": "domain", "value": "good.example.com"},
        ]
        bundle = build_stix_bundle(ssh_technique, iocs)
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        # Only 2 valid IOCs
        assert len(indicators) == 2

    def test_no_iocs_still_builds_bundle(self, ssh_technique):
        bundle = build_stix_bundle(ssh_technique, iocs=[], src_ip=None)
        assert bundle.type == "bundle"
        # identity + TLP + attack-pattern = 3 minimum
        assert len(bundle.objects) == 3

    def test_all_indicator_ids_unique(self, ssh_technique, multi_ioc_list):
        bundle = build_stix_bundle(ssh_technique, multi_ioc_list)
        indicator_ids = [o.id for o in bundle.objects if o.type == "indicator"]
        assert len(indicator_ids) == len(set(indicator_ids)), \
            "Indicator IDs must be unique"

    def test_all_relationship_ids_unique(self, ssh_technique, multi_ioc_list):
        bundle = build_stix_bundle(ssh_technique, multi_ioc_list)
        rel_ids = [o.id for o in bundle.objects if o.type == "relationship"]
        assert len(rel_ids) == len(set(rel_ids)), \
            "Relationship IDs must be unique"


# ===========================================================================
# 8. DIFFERENT ATTACK TYPES (SSH, HTTP, FTP, SMTP)
# ===========================================================================

class TestDifferentAttackTypes:
    """Verify bundles build correctly for each attack service type."""

    @pytest.mark.parametrize("fixture_name,expected_technique_id", [
        ("ssh_technique",  "T1110.001"),
        ("http_technique", "T1190"),
        ("ftp_technique",  "T1110.003"),
        ("smtp_technique", "T1566.001"),
        ("c2_technique",   "T1041"),
    ])
    def test_bundle_builds_for_attack_type(self, request, fixture_name, expected_technique_id):
        technique = request.getfixturevalue(fixture_name)
        iocs = [{"type": "ip", "value": "10.0.0.1"}]
        bundle = build_stix_bundle(technique, iocs)
        assert bundle.type == "bundle"
        aps = [o for o in bundle.objects if o.type == "attack-pattern"]
        assert aps[0].external_references[0].external_id == expected_technique_id

    def test_ssh_bundle_correct_phase(self, ssh_technique):
        bundle = build_stix_bundle(ssh_technique, [{"type": "ip", "value": "1.1.1.1"}])
        ap = next(o for o in bundle.objects if o.type == "attack-pattern")
        assert ap.kill_chain_phases[0].phase_name == "credential-access"

    def test_http_bundle_correct_phase(self, http_technique):
        bundle = build_stix_bundle(http_technique, [{"type": "ip", "value": "1.1.1.1"}])
        ap = next(o for o in bundle.objects if o.type == "attack-pattern")
        assert ap.kill_chain_phases[0].phase_name == "initial-access"

    def test_ftp_bundle_correct_phase(self, ftp_technique):
        bundle = build_stix_bundle(ftp_technique, [{"type": "ip", "value": "1.1.1.1"}])
        ap = next(o for o in bundle.objects if o.type == "attack-pattern")
        assert ap.kill_chain_phases[0].phase_name == "credential-access"

    def test_smtp_bundle_correct_phase(self, smtp_technique):
        bundle = build_stix_bundle(smtp_technique, [{"type": "ip", "value": "1.1.1.1"}])
        ap = next(o for o in bundle.objects if o.type == "attack-pattern")
        assert ap.kill_chain_phases[0].phase_name == "initial-access"

    def test_c2_bundle_exfiltration_phase(self, c2_technique):
        bundle = build_stix_bundle(c2_technique, [{"type": "ip", "value": "1.1.1.1"}])
        ap = next(o for o in bundle.objects if o.type == "attack-pattern")
        assert ap.kill_chain_phases[0].phase_name == "exfiltration"

    def test_ssh_ioc_pattern_in_bundle(self, ssh_technique):
        bundle = build_stix_bundle(ssh_technique, [{"type": "ip", "value": "185.220.101.42"}],
                                   src_ip="185.220.101.42")
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        assert any("185.220.101.42" in ind.pattern for ind in indicators)

    def test_http_domain_ioc_in_bundle(self, http_technique):
        iocs = [{"type": "domain", "value": "sqli-scanner.evil.com"}]
        bundle = build_stix_bundle(http_technique, iocs)
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        assert any("sqli-scanner.evil.com" in ind.pattern for ind in indicators)

    def test_smtp_email_ioc_in_bundle(self, smtp_technique):
        iocs = [{"type": "email", "value": "spear@phish.example"}]
        bundle = build_stix_bundle(smtp_technique, iocs)
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        assert any("spear@phish.example" in ind.pattern for ind in indicators)

    def test_ftp_url_ioc_in_bundle(self, ftp_technique):
        iocs = [{"type": "url", "value": "ftp://malware.dropzone.example/tool.exe"}]
        bundle = build_stix_bundle(ftp_technique, iocs)
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        assert any("ftp://malware.dropzone.example/tool.exe" in ind.pattern
                   for ind in indicators)


# ===========================================================================
# 9. TLP MARKING DEFINITIONS
# ===========================================================================

class TestTLPMarkingDefinitions:
    """Verify correct TLP markings are applied at the bundle level."""

    @pytest.mark.parametrize("tlp_level,expected_id", [
        ("white", stix2.TLP_WHITE.id),
        ("green", stix2.TLP_GREEN.id),
        ("amber", stix2.TLP_AMBER.id),
        ("red",   stix2.TLP_RED.id),
    ])
    def test_tlp_marking_definition_in_bundle(self, ssh_technique, tlp_level, expected_id):
        iocs = [{"type": "ip", "value": "1.1.1.1"}]
        bundle = build_stix_bundle(ssh_technique, iocs, tlp_level=tlp_level)
        marking_ids = {o.id for o in bundle.objects if o.type == "marking-definition"}
        assert expected_id in marking_ids

    @pytest.mark.parametrize("tlp_level", ["white", "green", "amber", "red"])
    def test_indicator_carries_correct_tlp(self, ssh_technique, tlp_level):
        expected_id_map = {
            "white": stix2.TLP_WHITE.id,
            "green": stix2.TLP_GREEN.id,
            "amber": stix2.TLP_AMBER.id,
            "red":   stix2.TLP_RED.id,
        }
        iocs = [{"type": "ip", "value": "1.1.1.1"}]
        bundle = build_stix_bundle(ssh_technique, iocs, tlp_level=tlp_level)
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        for ind in indicators:
            assert expected_id_map[tlp_level] in ind.object_marking_refs

    def test_invalid_tlp_defaults_to_white(self, ssh_technique):
        iocs = [{"type": "ip", "value": "1.1.1.1"}]
        bundle = build_stix_bundle(ssh_technique, iocs, tlp_level="invalid_color")
        marking_ids = {o.id for o in bundle.objects if o.type == "marking-definition"}
        assert stix2.TLP_WHITE.id in marking_ids

    def test_tlp_level_is_case_insensitive(self, ssh_technique):
        iocs = [{"type": "ip", "value": "1.1.1.1"}]
        bundle = build_stix_bundle(ssh_technique, iocs, tlp_level="GREEN")
        marking_ids = {o.id for o in bundle.objects if o.type == "marking-definition"}
        assert stix2.TLP_GREEN.id in marking_ids


# ===========================================================================
# 10. BUNDLE TIMESTAMP AND METADATA FIELDS
# ===========================================================================

class TestBundleMetadata:
    """Verify timestamps, created_by_ref, PhantomNet Identity, and metadata."""

    def test_phantomnet_identity_type(self):
        assert PHANTOMNET_IDENTITY.type == "identity"

    def test_phantomnet_identity_name(self):
        assert "PhantomNet" in PHANTOMNET_IDENTITY.name

    def test_phantomnet_identity_class(self):
        assert PHANTOMNET_IDENTITY.identity_class == "system"

    def test_phantomnet_identity_id_is_deterministic(self):
        """The identity ID must be stable (deterministic UUID5)."""
        expected = "identity--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "phantomnet.sentinel"))
        assert PHANTOMNET_IDENTITY.id == expected

    def test_bundle_identity_matches_phantomnet_identity(self, ssh_bundle):
        identity_in_bundle = next(
            (o for o in ssh_bundle.objects if o.type == "identity"), None
        )
        assert identity_in_bundle is not None
        assert identity_in_bundle.id == PHANTOMNET_IDENTITY.id

    def test_attack_pattern_has_created_timestamp(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.created is not None
        assert isinstance(ap.created, datetime)

    def test_attack_pattern_has_modified_timestamp(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.modified is not None
        assert isinstance(ap.modified, datetime)

    def test_attack_pattern_timestamps_are_utc(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        assert ap.created.tzinfo is not None

    def test_indicator_has_valid_from_timestamp(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        ind = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap.id)
        assert ind.valid_from is not None

    def test_indicator_custom_valid_from(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        vf = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        ind = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap.id, valid_from=vf)
        assert ind.valid_from == vf

    def test_bundle_json_contains_spec_version(self, ssh_bundle):
        json_str = bundle_to_json(ssh_bundle)
        assert '"spec_version": "2.1"' in json_str

    def test_bundle_json_contains_type_bundle(self, ssh_bundle):
        json_str = bundle_to_json(ssh_bundle)
        assert '"type": "bundle"' in json_str

    def test_bundle_json_is_pretty_printed_by_default(self, ssh_bundle):
        json_str = bundle_to_json(ssh_bundle)
        assert "\n" in json_str

    def test_bundle_json_compact_mode(self, ssh_bundle):
        json_str = bundle_to_json(ssh_bundle, pretty=False)
        assert "\n" not in json_str or json_str.count("\n") < 5  # minimal newlines

    def test_bundle_to_dict_round_trip(self, ssh_bundle):
        d = bundle_to_dict(ssh_bundle)
        assert d["type"] == "bundle"
        assert "objects" in d
        assert all("type" in obj for obj in d["objects"])


# ===========================================================================
# 11. DETERMINISTIC IDs
# ===========================================================================

class TestDeterministicIDs:
    """Verify that repeated calls with the same inputs produce the same IDs."""

    def test_attack_pattern_same_id_across_calls(self, ssh_technique):
        ap1 = build_attack_pattern(ssh_technique)
        ap2 = build_attack_pattern(ssh_technique)
        assert ap1.id == ap2.id

    def test_indicator_same_id_across_calls(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        ind1 = build_indicator({"type": "ip", "value": "10.0.0.1"}, ap.id)
        ind2 = build_indicator({"type": "ip", "value": "10.0.0.1"}, ap.id)
        assert ind1.id == ind2.id

    def test_different_ioc_values_produce_different_ids(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        ind1 = build_indicator({"type": "ip", "value": "1.1.1.1"}, ap.id)
        ind2 = build_indicator({"type": "ip", "value": "2.2.2.2"}, ap.id)
        assert ind1.id != ind2.id

    def test_different_ioc_types_produce_different_ids(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        ind1 = build_indicator({"type": "ip",     "value": "evil.com"}, ap.id)
        ind2 = build_indicator({"type": "domain", "value": "evil.com"}, ap.id)
        assert ind1.id != ind2.id

    def test_relationship_same_id_across_calls(self, ssh_technique):
        ap = build_attack_pattern(ssh_technique)
        ind = build_indicator({"type": "ip", "value": "10.0.0.1"}, ap.id)
        rel1 = build_relationship(ind.id, ap.id)
        rel2 = build_relationship(ind.id, ap.id)
        assert rel1.id == rel2.id

    def test_deterministic_stix_id_format(self):
        sid = _deterministic_stix_id("attack-pattern", "T1110")
        assert sid.startswith("attack-pattern--")
        uid = sid.replace("attack-pattern--", "")
        uuid.UUID(uid)  # must be valid UUID

    def test_deterministic_stix_id_same_seed(self):
        id1 = _deterministic_stix_id("indicator", "ip", "1.1.1.1", "attack-pattern--abc")
        id2 = _deterministic_stix_id("indicator", "ip", "1.1.1.1", "attack-pattern--abc")
        assert id1 == id2

    def test_deterministic_stix_id_different_seeds(self):
        id1 = _deterministic_stix_id("indicator", "ip", "1.1.1.1")
        id2 = _deterministic_stix_id("indicator", "ip", "2.2.2.2")
        assert id1 != id2


# ===========================================================================
# 12. IOC VALIDATION HELPER
# ===========================================================================

class TestIOCValidation:
    @pytest.mark.parametrize("ioc_type", list(_IOC_PATTERN_TEMPLATES.keys()))
    def test_valid_ioc_types_pass_validation(self, ioc_type):
        assert _validate_ioc({"type": ioc_type, "value": "somevalue"}) is True

    @pytest.mark.parametrize("bad_type", ["xml", "csv", "pdf", "exe", "", "unknown"])
    def test_invalid_ioc_types_fail_validation(self, bad_type):
        assert _validate_ioc({"type": bad_type, "value": "somevalue"}) is False

    def test_empty_value_fails_validation(self):
        assert _validate_ioc({"type": "ip", "value": ""}) is False

    def test_missing_type_fails_validation(self):
        assert _validate_ioc({"value": "1.1.1.1"}) is False

    def test_missing_value_fails_validation(self):
        assert _validate_ioc({"type": "ip"}) is False

    def test_case_insensitive_type_matching(self):
        assert _validate_ioc({"type": "IP", "value": "1.1.1.1"}) is True
        assert _validate_ioc({"type": "DOMAIN", "value": "evil.com"}) is True
