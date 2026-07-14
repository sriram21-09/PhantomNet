"""
backend/tests/test_llm_service.py
----------------------------------
Unit tests for backend/sentinel/llm_service.py

Covers:
  - Module-level helpers (backward-compatible public API):
      build_prompt, generate_fallback_narrative, generate_playbook_summary
  - LLMService class (Week 17, Day 1 deliverable):
      __init__, _validate_config, get_config,
      generate_narrative (disabled / enabled paths),
      trigger_narrative
"""

import os
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from sqlalchemy.orm import Session

from sentinel.llm_service import (
    # Module-level helpers (backward-compatible)
    build_prompt,
    generate_fallback_narrative,
    generate_playbook_summary,
    # New class-based API
    LLMService,
)


# ---------------------------------------------------------------------------
# Shared mock playbook fixture
# ---------------------------------------------------------------------------

class MockPlaybook:
    """Minimal SentinelPlaybook stand-in for unit tests."""

    def __init__(self):
        self.id = 1
        self.playbook_name = "SSH Brute Force Mitigations"
        self.attack_type = "Brute Force"
        self.technique_id = "T1021.004"
        self.technique_name = "SSH"
        self.tactic = "Lateral Movement"
        self.severity = "high"
        self.threat_score = 85
        self.src_ip = "192.168.1.100"
        self.dst_port = 22
        self.protocol = "TCP"
        self.llm_narrative = None
        self.updated_at = None


# ===========================================================================
# Module-level helper tests (preserved from original test suite)
# ===========================================================================

def test_build_prompt():
    """build_prompt should embed key playbook fields into the prompt string."""
    playbook = MockPlaybook()
    prompt = build_prompt(playbook)
    assert "SSH Brute Force Mitigations" in prompt
    assert "T1021.004" in prompt


def test_generate_fallback_narrative():
    """generate_fallback_narrative should return a Markdown local narrative."""
    playbook = MockPlaybook()
    narrative = generate_fallback_narrative(playbook)
    assert "### AI-Powered Playbook Narrative (Local Fallback)" in narrative
    assert "192.168.1.100" in narrative
    assert "85%" in narrative


@pytest.mark.anyio
@patch("sentinel.llm_service.httpx.AsyncClient")
async def test_generate_playbook_summary_success(mock_client_cls):
    """generate_playbook_summary should return and persist the LLM response."""
    mock_db = MagicMock(spec=Session)
    playbook = MockPlaybook()

    mock_query = mock_db.query.return_value
    mock_filter = mock_query.filter.return_value
    mock_filter.first.return_value = playbook

    # Mock httpx AsyncClient
    mock_client = AsyncMock()
    mock_client_cls.return_value.__aenter__.return_value = mock_client

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": "Custom LLM Summary Text"}
    mock_client.post.return_value = mock_response

    with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "true"}):
        result = await generate_playbook_summary(1, mock_db)

    assert result == "Custom LLM Summary Text"
    assert playbook.llm_narrative == "Custom LLM Summary Text"
    mock_db.commit.assert_called_once()


@pytest.mark.anyio
@patch("sentinel.llm_service.httpx.AsyncClient")
async def test_generate_playbook_summary_fallback_on_error(mock_client_cls):
    """generate_playbook_summary should fall back to local narrative on failure."""
    mock_db = MagicMock(spec=Session)
    playbook = MockPlaybook()

    mock_query = mock_db.query.return_value
    mock_filter = mock_query.filter.return_value
    mock_filter.first.return_value = playbook

    mock_client = AsyncMock()
    mock_client_cls.return_value.__aenter__.return_value = mock_client
    mock_client.post.side_effect = Exception("Ollama offline")

    with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "true"}):
        result = await generate_playbook_summary(1, mock_db)

    assert "### AI-Powered Playbook Narrative (Local Fallback)" in result
    assert playbook.llm_narrative == result
    mock_db.commit.assert_called_once()


# ===========================================================================
# LLMService class tests (Week 17, Day 1 deliverable)
# ===========================================================================

class TestLLMServiceInit:
    """Tests for LLMService.__init__ and _validate_config."""

    def test_disabled_by_default(self):
        """LLMService should be disabled when SENTINEL_LLM_ENABLED is not set."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SENTINEL_LLM_ENABLED", None)
            svc = LLMService()
        assert svc.enabled is False

    def test_enabled_via_env(self):
        """LLMService should be enabled when SENTINEL_LLM_ENABLED=true."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
        assert svc.enabled is True
        assert svc.host == "http://localhost:11434"
        assert svc.model == "mistral"

    def test_enabled_case_insensitive(self):
        """SENTINEL_LLM_ENABLED should accept 'TRUE', 'True', '1', 'yes', 'on'."""
        for value in ("TRUE", "True", "1", "yes", "on"):
            env = {
                "SENTINEL_LLM_ENABLED": value,
                "SENTINEL_LLM_HOST": "http://localhost:11434",
                "SENTINEL_LLM_MODEL": "mistral",
            }
            with patch.dict(os.environ, env):
                svc = LLMService()
            assert svc.enabled is True, f"Expected enabled=True for SENTINEL_LLM_ENABLED={value!r}"

    def test_validate_config_missing_host_raises(self):
        """_validate_config should raise EnvironmentError when HOST is empty."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            with pytest.raises(EnvironmentError, match="SENTINEL_LLM_HOST"):
                LLMService()

    def test_validate_config_invalid_host_raises(self):
        """_validate_config should raise EnvironmentError for malformed HOST."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "ollama:11434",   # missing scheme
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            with pytest.raises(EnvironmentError, match="http://"):
                LLMService()

    def test_validate_config_missing_model_raises(self):
        """_validate_config should raise EnvironmentError when MODEL is empty."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "",
        }
        with patch.dict(os.environ, env):
            with pytest.raises(EnvironmentError, match="SENTINEL_LLM_MODEL"):
                LLMService()

    def test_validate_config_skipped_when_disabled(self):
        """_validate_config should NOT raise when service is disabled."""
        env = {
            "SENTINEL_LLM_ENABLED": "false",
            "SENTINEL_LLM_HOST": "",           # would fail if validated
            "SENTINEL_LLM_MODEL": "",          # would fail if validated
        }
        with patch.dict(os.environ, env):
            svc = LLMService()   # must not raise
        assert svc.enabled is False


class TestLLMServiceGetConfig:
    """Tests for LLMService.get_config()."""

    def test_get_config_returns_dict(self):
        """get_config should return a dict with enabled, host, model."""
        env = {
            "SENTINEL_LLM_ENABLED": "false",
            "SENTINEL_LLM_HOST": "http://ollama:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
        cfg = svc.get_config()
        assert isinstance(cfg, dict)
        assert cfg["enabled"] is False
        assert cfg["host"] == "http://ollama:11434"
        assert cfg["model"] == "mistral"


class TestLLMServiceGenerateNarrative:
    """Tests for LLMService.generate_narrative()."""

    def test_returns_empty_string_when_disabled(self):
        """generate_narrative should return '' immediately when disabled."""
        with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "false"}):
            svc = LLMService()
        result = svc.generate_narrative({"attack_type": "Brute Force"})
        assert result == ""

    def test_returns_empty_string_for_empty_context(self):
        """generate_narrative should return '' when context_data is empty."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
        result = svc.generate_narrative({})
        assert result == ""

    def test_returns_empty_string_for_non_dict_context(self):
        """generate_narrative should return '' when context_data is not a dict."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
        result = svc.generate_narrative(None)  # type: ignore[arg-type]
        assert result == ""

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_generate_narrative_success(self, mock_client_cls):
        """generate_narrative should return the Ollama response on success."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "AI narrative text"}
        mock_client.post.return_value = mock_response

        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
            result = svc.generate_narrative({"attack_type": "Port Scan", "severity": "HIGH"})

        assert result == "AI narrative text"

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_generate_narrative_ollama_offline(self, mock_client_cls):
        """generate_narrative should return '' when Ollama is unreachable."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = Exception("Connection refused")

        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
            result = svc.generate_narrative({"attack_type": "SSH Brute Force"})

        assert result == ""

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_generate_narrative_non_200_response(self, mock_client_cls):
        """generate_narrative should return '' when Ollama returns non-200."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_client.post.return_value = mock_response

        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
            result = svc.generate_narrative({"attack_type": "SQLi"})

        assert result == ""


class TestLLMServiceTriggerNarrative:
    """Tests for LLMService.trigger_narrative()."""

    def test_trigger_narrative_delegates_to_module_function(self):
        """trigger_narrative should call trigger_llm_summary with the playbook_id."""
        with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "false"}):
            svc = LLMService()

        with patch("sentinel.llm_service.trigger_llm_summary") as mock_trigger:
            svc.trigger_narrative(42)
            mock_trigger.assert_called_once_with(42)
