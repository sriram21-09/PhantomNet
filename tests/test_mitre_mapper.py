"""
tests/test_mitre_mapper.py
--------------------------
Comprehensive unit tests for backend/sentinel/mitre_mapper.py

Coverage targets
~~~~~~~~~~~~~~~~
- get_technique()    : all 12 known signature → technique_id mappings,
                       unknown-signature returns None,
                       return schema validation (id, name, tactic, mitre_url)
- get_all_mappings() : returns a dict, contains exactly 12 entries,
                       all expected signature keys are present,
                       each value carries the mandatory ATT&CK fields,
                       returned dict is a copy (not the master table)

Week 4 – Day 1  |  PhantomNet Sentinel MITRE Mapper Tests
"""

from __future__ import annotations

import pytest
from sentinel.mitre_mapper import get_technique, get_all_mappings


# ---------------------------------------------------------------------------
# Constants – expected mapping table (signature → ATT&CK technique ID)
# ---------------------------------------------------------------------------

EXPECTED_MAPPINGS: dict[str, str] = {
    "SSH_AUTH_FAILURE":        "T1110.001",
    "SSH_HIGH_ACTIVITY":       "T1021.004",
    "HTTP_SQL_INJECTION":      "T1190",
    "HTTP_XSS_ATTEMPT":        "T1059.007",
    "HTTP_PATH_TRAVERSAL":     "T1083",
    "HTTP_SCANNER_BEHAVIOR":   "T1046",
    "FTP_DATA_EXFILTRATION":   "T1048.003",
    "SMTP_LARGE_PAYLOAD":      "T1071.003",
    "DISTRIBUTED_BRUTE_FORCE": "T1110.004",
    "LOW_AND_SLOW_SCAN":       "T1595.001",
    "MULTI_PROTOCOL_ATTACK":   "T1046",
    "HIGH_FREQUENCY_ATTACK":   "T1498",
}

# Slim-schema keys that get_technique() must always return
SLIM_SCHEMA_KEYS = {"id", "name", "tactic", "mitre_url"}

# Full ATT&CK fields required in every entry of get_all_mappings()
FULL_SCHEMA_KEYS = {
    "technique_id",
    "technique_name",
    "tactic",
    "tactic_id",
    "description",
    "url",
    "severity",
}

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
TOTAL_MAPPINGS = 12


# ===========================================================================
# Helper
# ===========================================================================

def _technique(sig: str) -> dict:
    """Call get_technique() and assert it is not None."""
    result = get_technique(sig)
    assert result is not None, f"get_technique({sig!r}) returned None unexpectedly"
    return result


# ===========================================================================
# Section 1 – Individual technique-ID assertions (one test per signature)
# ===========================================================================

class TestSSHAuthFailureMapping:
    """SSH_AUTH_FAILURE → T1110.001 (Brute Force: Password Guessing)"""

    def test_technique_id(self):
        assert _technique("SSH_AUTH_FAILURE")["id"] == "T1110.001"

    def test_tactic(self):
        assert _technique("SSH_AUTH_FAILURE")["tactic"] == "Credential Access"

    def test_name(self):
        assert _technique("SSH_AUTH_FAILURE")["name"] == "Brute Force: Password Guessing"

    def test_mitre_url_present(self):
        url = _technique("SSH_AUTH_FAILURE")["mitre_url"]
        assert url.startswith("https://attack.mitre.org/")


class TestSSHHighActivityMapping:
    """SSH_HIGH_ACTIVITY → T1021.004 (Remote Services: SSH)"""

    def test_technique_id(self):
        assert _technique("SSH_HIGH_ACTIVITY")["id"] == "T1021.004"

    def test_tactic(self):
        assert _technique("SSH_HIGH_ACTIVITY")["tactic"] == "Lateral Movement"

    def test_name(self):
        assert _technique("SSH_HIGH_ACTIVITY")["name"] == "Remote Services: SSH"


class TestHTTPSqlInjectionMapping:
    """HTTP_SQL_INJECTION → T1190 (Exploit Public-Facing Application)"""

    def test_technique_id(self):
        assert _technique("HTTP_SQL_INJECTION")["id"] == "T1190"

    def test_tactic(self):
        assert _technique("HTTP_SQL_INJECTION")["tactic"] == "Initial Access"

    def test_name(self):
        assert _technique("HTTP_SQL_INJECTION")["name"] == "Exploit Public-Facing Application"


class TestHTTPXssAttemptMapping:
    """HTTP_XSS_ATTEMPT → T1059.007 (Command and Scripting Interpreter: JavaScript)"""

    def test_technique_id(self):
        assert _technique("HTTP_XSS_ATTEMPT")["id"] == "T1059.007"

    def test_tactic(self):
        assert _technique("HTTP_XSS_ATTEMPT")["tactic"] == "Execution"

    def test_name(self):
        assert (
            _technique("HTTP_XSS_ATTEMPT")["name"]
            == "Command and Scripting Interpreter: JavaScript"
        )


class TestHTTPPathTraversalMapping:
    """HTTP_PATH_TRAVERSAL → T1083 (File and Directory Discovery)"""

    def test_technique_id(self):
        assert _technique("HTTP_PATH_TRAVERSAL")["id"] == "T1083"

    def test_tactic(self):
        assert _technique("HTTP_PATH_TRAVERSAL")["tactic"] == "Discovery"

    def test_name(self):
        assert _technique("HTTP_PATH_TRAVERSAL")["name"] == "File and Directory Discovery"


class TestHTTPScannerBehaviorMapping:
    """HTTP_SCANNER_BEHAVIOR → T1046 (Network Service Discovery)"""

    def test_technique_id(self):
        assert _technique("HTTP_SCANNER_BEHAVIOR")["id"] == "T1046"

    def test_tactic(self):
        assert _technique("HTTP_SCANNER_BEHAVIOR")["tactic"] == "Discovery"

    def test_name(self):
        assert _technique("HTTP_SCANNER_BEHAVIOR")["name"] == "Network Service Discovery"


class TestFTPDataExfiltrationMapping:
    """FTP_DATA_EXFILTRATION → T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol)"""

    def test_technique_id(self):
        assert _technique("FTP_DATA_EXFILTRATION")["id"] == "T1048.003"

    def test_tactic(self):
        assert _technique("FTP_DATA_EXFILTRATION")["tactic"] == "Exfiltration"

    def test_name(self):
        assert (
            _technique("FTP_DATA_EXFILTRATION")["name"]
            == "Exfiltration Over Unencrypted Non-C2 Protocol"
        )


class TestSMTPLargePayloadMapping:
    """SMTP_LARGE_PAYLOAD → T1071.003 (Application Layer Protocol: Mail Protocols)"""

    def test_technique_id(self):
        assert _technique("SMTP_LARGE_PAYLOAD")["id"] == "T1071.003"

    def test_tactic(self):
        assert _technique("SMTP_LARGE_PAYLOAD")["tactic"] == "Command and Control"

    def test_name(self):
        assert (
            _technique("SMTP_LARGE_PAYLOAD")["name"]
            == "Application Layer Protocol: Mail Protocols"
        )


class TestDistributedBruteForceMapping:
    """DISTRIBUTED_BRUTE_FORCE → T1110.004 (Brute Force: Credential Stuffing)"""

    def test_technique_id(self):
        assert _technique("DISTRIBUTED_BRUTE_FORCE")["id"] == "T1110.004"

    def test_tactic(self):
        assert _technique("DISTRIBUTED_BRUTE_FORCE")["tactic"] == "Credential Access"

    def test_name(self):
        assert _technique("DISTRIBUTED_BRUTE_FORCE")["name"] == "Brute Force: Credential Stuffing"


class TestLowAndSlowScanMapping:
    """LOW_AND_SLOW_SCAN → T1595.001 (Active Scanning: Scanning IP Blocks)"""

    def test_technique_id(self):
        assert _technique("LOW_AND_SLOW_SCAN")["id"] == "T1595.001"

    def test_tactic(self):
        assert _technique("LOW_AND_SLOW_SCAN")["tactic"] == "Reconnaissance"

    def test_name(self):
        assert _technique("LOW_AND_SLOW_SCAN")["name"] == "Active Scanning: Scanning IP Blocks"


class TestMultiProtocolAttackMapping:
    """MULTI_PROTOCOL_ATTACK → T1046 (Network Service Discovery)"""

    def test_technique_id(self):
        assert _technique("MULTI_PROTOCOL_ATTACK")["id"] == "T1046"

    def test_tactic(self):
        assert _technique("MULTI_PROTOCOL_ATTACK")["tactic"] == "Discovery"

    def test_name(self):
        assert _technique("MULTI_PROTOCOL_ATTACK")["name"] == "Network Service Discovery"


class TestHighFrequencyAttackMapping:
    """HIGH_FREQUENCY_ATTACK → T1498 (Network Denial of Service)"""

    def test_technique_id(self):
        assert _technique("HIGH_FREQUENCY_ATTACK")["id"] == "T1498"

    def test_tactic(self):
        assert _technique("HIGH_FREQUENCY_ATTACK")["tactic"] == "Impact"

    def test_name(self):
        assert _technique("HIGH_FREQUENCY_ATTACK")["name"] == "Network Denial of Service"


# ===========================================================================
# Section 2 – Parametrised sweep over all 12 expected technique IDs
# ===========================================================================

class TestAllTechniqueIDsParametrized:
    """Parametrised batch check: every signature returns its exact technique ID."""

    @pytest.mark.parametrize("signature,expected_id", list(EXPECTED_MAPPINGS.items()))
    def test_technique_id(self, signature: str, expected_id: str):
        result = get_technique(signature)
        assert result is not None, (
            f"get_technique({signature!r}) returned None; expected technique_id={expected_id!r}"
        )
        assert result["id"] == expected_id, (
            f"Signature {signature!r}: expected id={expected_id!r}, got {result['id']!r}"
        )

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_slim_schema_keys(self, signature: str):
        """Every mapped signature must return a dict with exactly the slim-schema keys."""
        result = get_technique(signature)
        assert result is not None
        assert set(result.keys()) == SLIM_SCHEMA_KEYS, (
            f"Signature {signature!r} returned keys {set(result.keys())} "
            f"instead of {SLIM_SCHEMA_KEYS}"
        )

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_mitre_url_is_valid_string(self, signature: str):
        """mitre_url must be a non-empty string starting with the ATT&CK base URL."""
        result = get_technique(signature)
        assert result is not None
        url = result["mitre_url"]
        assert isinstance(url, str) and url.startswith("https://attack.mitre.org/"), (
            f"Signature {signature!r} has invalid mitre_url: {url!r}"
        )


# ===========================================================================
# Section 3 – Unknown / invalid signature handling
# ===========================================================================

class TestUnknownSignatureReturnsNone:
    """get_technique() must return None for any unmapped / invalid input."""

    def test_completely_unknown_signature(self):
        assert get_technique("COMPLETELY_UNKNOWN_SIGNATURE") is None

    def test_empty_string(self):
        assert get_technique("") is None

    def test_lowercase_known_signature(self):
        """Mapping is case-sensitive; lowercase should not match."""
        assert get_technique("ssh_auth_failure") is None

    def test_partial_signature(self):
        assert get_technique("SSH") is None

    def test_none_like_string(self):
        assert get_technique("None") is None

    def test_numeric_string(self):
        assert get_technique("12345") is None

    def test_whitespace_only(self):
        assert get_technique("   ") is None

    def test_signature_with_trailing_space(self):
        """Exact match only; trailing whitespace must not match."""
        assert get_technique("SSH_AUTH_FAILURE ") is None

    def test_signature_with_leading_space(self):
        assert get_technique(" SSH_AUTH_FAILURE") is None

    def test_mixed_case_signature(self):
        assert get_technique("Http_Sql_Injection") is None

    def test_sql_injection_typo(self):
        assert get_technique("HTTP_SQL_INJECTIONS") is None  # pluralised typo


# ===========================================================================
# Section 4 – get_all_mappings() completeness and integrity
# ===========================================================================

class TestGetAllMappings:
    """Tests for get_all_mappings() return value."""

    # -- Fixtures -----------------------------------------------------------

    @pytest.fixture
    def all_mappings(self) -> dict:
        return get_all_mappings()

    # -- Type and size ------------------------------------------------------

    def test_returns_dict(self, all_mappings):
        assert isinstance(all_mappings, dict), (
            f"get_all_mappings() should return dict, got {type(all_mappings).__name__}"
        )

    def test_exactly_12_entries(self, all_mappings):
        assert len(all_mappings) == TOTAL_MAPPINGS, (
            f"Expected {TOTAL_MAPPINGS} mappings, got {len(all_mappings)}"
        )

    # -- Key presence -------------------------------------------------------

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_all_expected_signature_keys_present(self, signature: str):
        mappings = get_all_mappings()
        assert signature in mappings, (
            f"Signature {signature!r} is missing from get_all_mappings()"
        )

    # -- Value schema -------------------------------------------------------

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_value_contains_required_fields(self, signature: str):
        mappings = get_all_mappings()
        value = mappings[signature]
        missing = FULL_SCHEMA_KEYS - set(value.keys())
        assert not missing, (
            f"Signature {signature!r} value is missing fields: {missing}"
        )

    @pytest.mark.parametrize("signature,expected_id", list(EXPECTED_MAPPINGS.items()))
    def test_technique_id_matches_expected(self, signature: str, expected_id: str):
        mappings = get_all_mappings()
        assert mappings[signature]["technique_id"] == expected_id, (
            f"Signature {signature!r}: expected technique_id={expected_id!r}, "
            f"got {mappings[signature]['technique_id']!r}"
        )

    # -- Severity values ----------------------------------------------------

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_severity_is_valid(self, signature: str):
        mappings = get_all_mappings()
        sev = mappings[signature]["severity"]
        assert sev in VALID_SEVERITIES, (
            f"Signature {signature!r} has unrecognised severity: {sev!r}"
        )

    # -- Isolation (returned copy must not expose master table) -------------

    def test_mutation_does_not_affect_master_table(self):
        """Modifying the returned dict must not alter subsequent calls."""
        m1 = get_all_mappings()
        m1["INJECTED_KEY"] = {"technique_id": "T9999"}
        m2 = get_all_mappings()
        assert "INJECTED_KEY" not in m2, (
            "get_all_mappings() must return a copy; master table was mutated"
        )

    def test_two_calls_return_equal_dicts(self):
        """Repeated calls must produce identical results."""
        assert get_all_mappings() == get_all_mappings()

    def test_returned_dict_has_no_signature_field(self):
        """Values in get_all_mappings() must NOT have 'signature' injected."""
        for sig, value in get_all_mappings().items():
            assert "signature" not in value, (
                f"get_all_mappings()[{sig!r}] unexpectedly contains 'signature' key"
            )

    # -- tactic_id sanity (all must start with 'TA') -------------------------

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_tactic_id_format(self, signature: str):
        mappings = get_all_mappings()
        tactic_id = mappings[signature]["tactic_id"]
        assert tactic_id.startswith("TA"), (
            f"Signature {signature!r}: tactic_id={tactic_id!r} does not start with 'TA'"
        )

    # -- URL reachability (format only, no network call) --------------------

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_url_points_to_attack_mitre_org(self, signature: str):
        mappings = get_all_mappings()
        url = mappings[signature]["url"]
        assert url.startswith("https://attack.mitre.org/techniques/"), (
            f"Signature {signature!r}: URL {url!r} does not point to ATT&CK techniques"
        )

    # -- Description is non-empty string ------------------------------------

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_description_is_non_empty(self, signature: str):
        mappings = get_all_mappings()
        desc = mappings[signature]["description"]
        assert isinstance(desc, str) and len(desc.strip()) > 0, (
            f"Signature {signature!r} has an empty or non-string description"
        )


# ===========================================================================
# Section 5 – Cross-function consistency
# ===========================================================================

class TestCrossAPIConsistency:
    """Ensure get_technique() and get_all_mappings() are mutually consistent."""

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_get_technique_id_matches_get_all_mappings(self, signature: str):
        slim = get_technique(signature)
        full = get_all_mappings()[signature]
        assert slim["id"] == full["technique_id"], (
            f"Signature {signature!r}: get_technique().id={slim['id']!r} "
            f"!= get_all_mappings()[...].technique_id={full['technique_id']!r}"
        )

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_get_technique_name_matches_get_all_mappings(self, signature: str):
        slim = get_technique(signature)
        full = get_all_mappings()[signature]
        assert slim["name"] == full["technique_name"]

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_get_technique_tactic_matches_get_all_mappings(self, signature: str):
        slim = get_technique(signature)
        full = get_all_mappings()[signature]
        assert slim["tactic"] == full["tactic"]

    @pytest.mark.parametrize("signature", list(EXPECTED_MAPPINGS.keys()))
    def test_get_technique_url_matches_get_all_mappings(self, signature: str):
        slim = get_technique(signature)
        full = get_all_mappings()[signature]
        assert slim["mitre_url"] == full["url"]
