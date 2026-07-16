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
os.environ["ENVIRONMENT"] = "test"
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

    assert result == "Custom LLM Summary Text\n"
    assert playbook.llm_narrative == "Custom LLM Summary Text\n"
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

@pytest.mark.anyio
async def test_api_get_llm_status():
    """Verify get_llm_status endpoint function returns configuration and health status."""
    from api.sentinel import get_llm_status
    from unittest.mock import patch, AsyncMock, MagicMock

    with patch("httpx.AsyncClient") as mock_client_cls:
        # Mock client connection success
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client.get.return_value = mock_response

        data = await get_llm_status()
        assert data["status"] == "success"
        assert "enabled" in data
        assert "model" in data
        assert "host" in data
        assert data["host_connection_status"] == "online"

    with patch("httpx.AsyncClient") as mock_client_cls:
        # Mock client connection failure
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get.side_effect = Exception("Ollama connection timed out")

        data = await get_llm_status()
        assert data["status"] == "success"
        assert data["host_connection_status"] == "offline"



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
        """generate_narrative should return fallback immediately when disabled."""
        with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "false"}):
            svc = LLMService()
        result = svc.generate_narrative({"attack_type": "Brute Force"})
        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    def test_returns_empty_string_for_empty_context(self):
        """generate_narrative should return fallback when context_data is empty."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
        result = svc.generate_narrative({})
        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    def test_returns_empty_string_for_non_dict_context(self):
        """generate_narrative should return fallback when context_data is not a dict."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
        result = svc.generate_narrative(None)  # type: ignore[arg-type]
        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

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

        assert result == "AI narrative text\n"

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_generate_narrative_ollama_offline(self, mock_client_cls):
        """generate_narrative should return fallback when Ollama is unreachable."""
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

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_generate_narrative_non_200_response(self, mock_client_cls):
        """generate_narrative should return fallback when Ollama returns non-200."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 503
        import httpx
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("503 error", request=MagicMock(), response=mock_response)
        mock_client.post.return_value = mock_response

        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()
            result = svc.generate_narrative({"attack_type": "SQLi"})

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result


class TestLLMServiceTriggerNarrative:
    """Tests for LLMService.trigger_narrative()."""

    def test_trigger_narrative_delegates_to_module_function(self):
        """trigger_narrative should call trigger_llm_summary with the playbook_id."""
        with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "false"}):
            svc = LLMService()

        with patch("sentinel.llm_service.trigger_llm_summary") as mock_trigger:
            svc.trigger_narrative(42)
            mock_trigger.assert_called_once_with(42)


class TestLLMServiceDynamicDatabaseToggle:
    """Tests for dynamic database toggles on LLMService and related APIs."""

    def test_enabled_property_dynamic_db(self):
        """enabled property should check database and override environment config."""
        from database.models import SystemConfig
        
        # Scenario A: DB config is set to "true"
        mock_cfg = SystemConfig(key="sentinel_llm_enabled", value="true")
        
        with patch("database.database.SessionLocal") as mock_session_local:
            mock_db = MagicMock()
            mock_session_local.return_value = mock_db
            mock_db.query.return_value.filter.return_value.first.return_value = mock_cfg
            
            # Set TEST_DB_TOGGLE so database checks are performed during testing
            with patch.dict(os.environ, {"TEST_DB_TOGGLE": "true", "SENTINEL_LLM_ENABLED": "false"}):
                svc = LLMService()
                # Should be True because database overrides env config (which is false)
                assert svc.enabled is True

        # Scenario B: DB config is set to "false"
        mock_cfg_false = SystemConfig(key="sentinel_llm_enabled", value="false")
        with patch("database.database.SessionLocal") as mock_session_local:
            mock_db = MagicMock()
            mock_session_local.return_value = mock_db
            mock_db.query.return_value.filter.return_value.first.return_value = mock_cfg_false
            
            with patch.dict(os.environ, {"TEST_DB_TOGGLE": "true", "SENTINEL_LLM_ENABLED": "true"}):
                svc = LLMService()
                # Should be False because database overrides env config (which is true)
                assert svc.enabled is False

    @pytest.mark.anyio
    @patch("sentinel.llm_service.httpx.AsyncClient")
    async def test_generate_playbook_summary_dynamic_db(self, mock_client_cls):
        """generate_playbook_summary should dynamically check database and call LLM API when enabled."""
        from database.models import SystemConfig
        from sentinel.models import SentinelPlaybook
        
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "DB-enabled AI narrative"}
        mock_client.post.return_value = mock_response

        # Scenario: DB toggle is "true"
        mock_db = MagicMock()
        mock_playbook = MockPlaybook()
        mock_cfg = SystemConfig(key="sentinel_llm_enabled", value="true")

        # Mock DB query flow
        # First query: SentinelPlaybook
        # Second query: SystemConfig
        def mock_query(model):
            q = MagicMock()
            if model == SentinelPlaybook:
                q.filter.return_value.first.return_value = mock_playbook
            elif model == SystemConfig:
                q.filter.return_value.first.return_value = mock_cfg
            return q

        mock_db.query.side_effect = mock_query

        # Run with TEST_DB_TOGGLE=true so it doesn't fall back to test env defaults
        with patch.dict(os.environ, {"TEST_DB_TOGGLE": "true", "SENTINEL_LLM_ENABLED": "false"}):
            res = await generate_playbook_summary(1, db=mock_db)
            assert res == "DB-enabled AI narrative\n"

    @pytest.mark.anyio
    @patch("sentinel.llm_service.httpx.AsyncClient")
    async def test_get_llm_status_dynamic_db(self, mock_client_cls):
        """get_llm_status endpoint should reflect dynamic database configuration."""
        from database.models import SystemConfig
        from api.sentinel import get_llm_status
        
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client.get.return_value = mock_response

        # Database set to "true"
        mock_cfg = SystemConfig(key="sentinel_llm_enabled", value="true")
        
        with patch("database.database.SessionLocal") as mock_session_local:
            mock_db = MagicMock()
            mock_session_local.return_value = mock_db
            mock_db.query.return_value.filter.return_value.first.return_value = mock_cfg
            
            with patch.dict(os.environ, {"TEST_DB_TOGGLE": "true", "SENTINEL_LLM_ENABLED": "false"}):
                status_res = await get_llm_status()
                assert status_res["enabled"] is True
