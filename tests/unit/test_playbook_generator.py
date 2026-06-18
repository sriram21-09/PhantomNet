"""
tests/unit/test_playbook_generator.py
--------------------------------------
Unit tests for sentinel.playbook_generator.PlaybookGenerator.

Covers:
- Initialization and Jinja2 environment setup
- Template selection logic for all supported attack patterns
- Full render-and-parse cycle for brute_force and port_scan
- validate_context() guard-rails
- list_templates() discovery
- Error paths: missing pattern, unknown template, wrong context type
"""

import pytest
import yaml
from sentinel.playbook_generator import PlaybookGenerator


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def gen() -> PlaybookGenerator:
    """Return a default PlaybookGenerator instance."""
    return PlaybookGenerator()


# ============================================================
# Initialization
# ============================================================

class TestInit:
    def test_instance_created(self, gen):
        assert gen is not None

    def test_jinja2_env_configured(self, gen):
        assert gen.env is not None

    def test_loader_attached(self, gen):
        assert gen.loader is not None

    def test_templates_dir_is_absolute(self, gen):
        import os
        assert os.path.isabs(gen.templates_dir)

    def test_custom_templates_dir(self, tmp_path):
        g = PlaybookGenerator(templates_dir=str(tmp_path))
        assert g.templates_dir == str(tmp_path)


# ============================================================
# Template selection
# ============================================================

class TestSelectTemplate:
    @pytest.mark.parametrize("pattern,expected", [
        ("brute_force",                   "brute_force_response.yaml.j2"),
        ("brute-force",                   "brute_force_response.yaml.j2"),
        ("failed_login",                  "brute_force_response.yaml.j2"),
        ("SSH_BRUTE_FORCE_DISTRIBUTED",   "brute_force_response.yaml.j2"),
        ("port_scan",                     "port_scan_response.yaml.j2"),
        ("port-scan",                     "port_scan_response.yaml.j2"),
        ("scan",                          "port_scan_response.yaml.j2"),
        ("credential_reuse",              "credential_reuse_response.yaml.j2"),
        ("credential-reuse",              "credential_reuse_response.yaml.j2"),
        ("honeytoken",                    "credential_reuse_response.yaml.j2"),
        ("distributed_attack",            "distributed_attack_response.yaml.j2"),
        ("distributed-attack",            "distributed_attack_response.yaml.j2"),
        ("distributed",                   "distributed_attack_response.yaml.j2"),
    ])
    def test_known_patterns(self, gen, pattern, expected):
        assert gen._select_template(pattern) == expected

    def test_fallback_unknown_pattern(self, gen):
        assert gen._select_template("custom_pattern") == "custom_pattern_response.yaml.j2"

    def test_empty_pattern_raises(self, gen):
        with pytest.raises(ValueError):
            gen._select_template("")

    def test_none_pattern_raises(self, gen):
        with pytest.raises((ValueError, AttributeError)):
            gen._select_template(None)


# ============================================================
# validate_context
# ============================================================

class TestValidateContext:
    def test_valid_context_passes(self, gen):
        gen.validate_context({"attack_pattern": "brute_force"})

    def test_missing_attack_pattern_raises(self, gen):
        with pytest.raises(ValueError, match="attack_pattern"):
            gen.validate_context({"source_ip": "1.1.1.1"})

    def test_empty_attack_pattern_raises(self, gen):
        with pytest.raises(ValueError, match="attack_pattern"):
            gen.validate_context({"attack_pattern": ""})

    def test_non_dict_raises(self, gen):
        with pytest.raises(TypeError):
            gen.validate_context(["attack_pattern", "brute_force"])


# ============================================================
# list_templates
# ============================================================

class TestListTemplates:
    def test_returns_list(self, gen):
        templates = gen.list_templates()
        assert isinstance(templates, list)

    def test_all_yaml_j2(self, gen):
        for t in gen.list_templates():
            assert t.endswith(".yaml.j2")

    def test_expected_templates_present(self, gen):
        templates = gen.list_templates()
        assert "brute_force_response.yaml.j2" in templates
        assert "port_scan_response.yaml.j2" in templates
        assert "credential_reuse_response.yaml.j2" in templates
        assert "distributed_attack_response.yaml.j2" in templates

    def test_sorted_order(self, gen):
        templates = gen.list_templates()
        assert templates == sorted(templates)


# ============================================================
# generate() – brute_force
# ============================================================

class TestGenerateBruteForce:
    def test_returns_non_empty_string(self, gen):
        rendered = gen.generate({
            "attack_pattern": "brute_force",
            "source_ip": "192.168.1.100",
        })
        assert isinstance(rendered, str)
        assert len(rendered) > 0

    def test_valid_yaml_output(self, gen):
        rendered = gen.generate({
            "attack_pattern": "brute_force",
            "source_ip": "192.168.1.100",
        })
        data = yaml.safe_load(rendered)
        assert isinstance(data, dict)

    def test_variables_substituted(self, gen):
        context = {
            "attack_pattern": "brute_force",
            "source_ip": "192.168.1.100",
            "failed_logins_threshold": 30,
            "timeframe": "10 minutes",
            "timeframe_seconds": "600s",
            "block_duration": "7200",
            "tarpit_delay_ms": 3000,
            "alert_level": "CRITICAL",
        }
        data = yaml.safe_load(gen.generate(context))
        assert data["name"] == "Brute Force Response"
        assert "Triggered when failed logins exceed 30" in data["description"]

        actions = data["actions"]
        assert actions[0]["name"] == "block_attacker_ip"
        assert actions[0]["params"]["ip"] == "192.168.1.100"
        assert actions[0]["params"]["duration"] == "7200"
        assert actions[1]["name"] == "tarpit_connection"
        assert actions[1]["params"]["delay_ms"] == 3000
        assert actions[2]["params"]["level"] == "CRITICAL"

    def test_default_values_applied(self, gen):
        # Only the required key – all others should use Jinja2 defaults
        data = yaml.safe_load(gen.generate({"attack_pattern": "brute_force"}))
        actions = data["actions"]
        assert actions[0]["params"]["duration"] == "3600"
        assert actions[2]["params"]["level"] == "HIGH"


# ============================================================
# generate() – port_scan
# ============================================================

class TestGeneratePortScan:
    def test_correct_name(self, gen):
        data = yaml.safe_load(gen.generate({
            "attack_pattern": "port_scan",
            "source_ip": "10.0.0.5",
            "port_count_threshold": 100,
            "capture_duration": "600s",
        }))
        assert data["name"] == "Port Scan Response"

    def test_ip_rendered(self, gen):
        data = yaml.safe_load(gen.generate({
            "attack_pattern": "port_scan",
            "source_ip": "10.0.0.5",
            "capture_duration": "600s",
        }))
        assert data["actions"][0]["params"]["ip"] == "10.0.0.5"
        assert data["actions"][0]["params"]["duration"] == "600s"

    def test_default_honeypot_count(self, gen):
        data = yaml.safe_load(gen.generate({"attack_pattern": "port_scan"}))
        assert data["actions"][1]["params"]["count"] == 3


# ============================================================
# generate() – credential_reuse
# ============================================================

class TestGenerateCredentialReuse:
    def test_correct_name(self, gen):
        data = yaml.safe_load(gen.generate({"attack_pattern": "credential_reuse"}))
        assert data["name"] == "Credential Reuse Detection"

    def test_default_alert_level_critical(self, gen):
        data = yaml.safe_load(gen.generate({"attack_pattern": "honeytoken"}))
        assert data["actions"][0]["params"]["level"] == "CRITICAL"


# ============================================================
# generate() – distributed_attack
# ============================================================

class TestGenerateDistributedAttack:
    def test_correct_name(self, gen):
        data = yaml.safe_load(gen.generate({"attack_pattern": "distributed_attack"}))
        assert data["name"] == "Distributed Attack Response"

    def test_default_ioc_format(self, gen):
        data = yaml.safe_load(gen.generate({"attack_pattern": "distributed"}))
        share_action = next(
            a for a in data["actions"] if a["name"] == "share_iocs"
        )
        assert share_action["params"]["format"] == "STIX"


# ============================================================
# Error paths
# ============================================================

class TestErrorPaths:
    def test_missing_attack_pattern_raises_value_error(self, gen):
        with pytest.raises(ValueError, match="attack_pattern"):
            gen.generate({"source_ip": "1.1.1.1"})

    def test_unknown_pattern_raises_file_not_found(self, gen):
        with pytest.raises(FileNotFoundError, match="unknown_pattern_response.yaml.j2"):
            gen.generate({"attack_pattern": "unknown_pattern"})

    def test_non_dict_context_raises_type_error(self, gen):
        with pytest.raises(TypeError):
            gen.generate("not_a_dict")
