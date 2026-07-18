"""
backend/tests/test_llm_service_integration.py
----------------------------------------------
Integration tests for backend/sentinel/llm_service.py

Week 17, Day 5 deliverable — covers:
  1. Toggle behavior (enabled/disabled states)
  2. Timeout exception handling
  3. Graceful fallback when Ollama API errors occur
  4. Mock client mode
  5. End-to-end narrative generation pipeline
  6. Async narrative generation
  7. Markdown post-processing pipeline
  8. Prompt building pipeline (legacy + structured)
"""

import os
os.environ["ENVIRONMENT"] = "test"

import asyncio
import json
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from sqlalchemy.orm import Session

import httpx

from sentinel.llm_service import (
    LLMService,
    build_prompt,
    generate_fallback_narrative,
    generate_playbook_summary,
    trigger_llm_summary,
    _OLLAMA_TIMEOUT,
)


# ---------------------------------------------------------------------------
# Shared fixtures & helpers
# ---------------------------------------------------------------------------

class MockPlaybook:
    """Minimal SentinelPlaybook stand-in for integration tests."""

    def __init__(self, **overrides):
        defaults = dict(
            id=1,
            playbook_name="SSH Brute Force Mitigations",
            attack_type="Brute Force",
            technique_id="T1021.004",
            technique_name="SSH",
            tactic="Lateral Movement",
            severity="HIGH",
            threat_score=85,
            src_ip="192.168.1.100",
            dst_port=22,
            protocol="TCP",
            llm_narrative=None,
            updated_at=None,
        )
        defaults.update(overrides)
        for k, v in defaults.items():
            setattr(self, k, v)


SAMPLE_CONTEXT = {
    "attack_type": "SSH_AUTH_FAILURE",
    "severity": "HIGH",
    "src_ip": "10.0.0.1",
    "dst_port": 2222,
    "protocol": "TCP",
    "technique_id": "T1110",
    "technique_name": "Brute Force",
    "tactic": "Credential Access",
    "threat_score": 78.5,
    "event_count": 42,
    "campaign_id": "CAMP-INT-001",
}


def _make_disabled_svc():
    """Create an LLMService with LLM disabled."""
    with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "false"}):
        svc = LLMService()
    return svc


def _make_enabled_svc(**extra_env):
    """Create an LLMService with LLM enabled and valid config."""
    env = {
        "SENTINEL_LLM_ENABLED": "true",
        "SENTINEL_LLM_HOST": "http://localhost:11434",
        "SENTINEL_LLM_MODEL": "mistral",
    }
    env.update(extra_env)
    with patch.dict(os.environ, env):
        svc = LLMService()
    return svc


# ===========================================================================
# 1. Toggle Behavior — Enabled / Disabled States
# ===========================================================================

class TestToggleBehavior:
    """Integration tests for LLM enabled/disabled toggle behavior."""

    def test_disabled_returns_fallback_narrative(self):
        """When disabled, generate_narrative returns a structured fallback."""
        svc = _make_disabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result
        assert "10.0.0.1" in result
        assert "SSH_AUTH_FAILURE" in result

    def test_disabled_skips_ollama_call(self):
        """When disabled, no HTTP call should be made to Ollama."""
        svc = _make_disabled_svc()
        with patch("sentinel.llm_service.httpx.AsyncClient") as mock_client:
            svc.generate_narrative(SAMPLE_CONTEXT)
            mock_client.assert_not_called()

    @pytest.mark.anyio
    async def test_async_disabled_returns_empty_string(self):
        """When disabled, async_generate_narrative returns empty string."""
        svc = _make_disabled_svc()
        result = await svc.async_generate_narrative(SAMPLE_CONTEXT)
        assert result == ""

    def test_enabled_override_via_setter(self):
        """Setting svc.enabled = True/False should override env config."""
        svc = _make_disabled_svc()
        assert svc.enabled is False

        svc.enabled = True
        assert svc.enabled is True

        svc.enabled = False
        assert svc.enabled is False

    def test_dynamic_database_toggle_enabled(self):
        """enabled property reads from database SystemConfig when available."""
        from database.models import SystemConfig

        mock_cfg = SystemConfig(key="sentinel_llm_enabled", value="true")
        with patch("database.database.SessionLocal") as mock_sl:
            mock_db = MagicMock()
            mock_sl.return_value = mock_db
            mock_db.query.return_value.filter.return_value.first.return_value = mock_cfg

            with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "false"}):
                svc = LLMService()
                # Database says true → should be enabled
                assert svc.enabled is True

    def test_dynamic_database_toggle_disabled(self):
        """enabled returns False when database SystemConfig is 'false'."""
        from database.models import SystemConfig

        mock_cfg = SystemConfig(key="sentinel_llm_enabled", value="false")
        with patch("database.database.SessionLocal") as mock_sl:
            mock_db = MagicMock()
            mock_sl.return_value = mock_db
            mock_db.query.return_value.filter.return_value.first.return_value = mock_cfg

            with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "true"}):
                svc = LLMService()
                assert svc.enabled is False

    def test_toggle_transition_enabled_to_disabled(self):
        """Switching from enabled to disabled mid-flight returns fallback."""
        svc = _make_enabled_svc()
        assert svc.enabled is True

        # Disable mid-flight
        svc.enabled = False
        result = svc.generate_narrative(SAMPLE_CONTEXT)
        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    def test_get_config_reflects_toggle_state(self):
        """get_config() should reflect current enabled state."""
        svc = _make_disabled_svc()
        cfg = svc.get_config()
        assert cfg["enabled"] is False

        svc.enabled = True
        cfg = svc.get_config()
        assert cfg["enabled"] is True


# ===========================================================================
# 2. Timeout Exception Handling
# ===========================================================================

class TestTimeoutHandling:
    """Integration tests for httpx timeout exception handling."""

    def test_timeout_constants_are_configured(self):
        """Verify the 60-second timeout constants are correctly set."""
        assert _OLLAMA_TIMEOUT.connect == 60.0
        assert _OLLAMA_TIMEOUT.read == 60.0
        assert _OLLAMA_TIMEOUT.write == 10.0
        assert _OLLAMA_TIMEOUT.pool == 5.0

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_connect_timeout_returns_fallback(self, mock_client_cls):
        """ConnectTimeout should trigger fallback narrative."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = httpx.ConnectTimeout(
            "Connection timed out after 60s"
        )

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result
        assert "10.0.0.1" in result

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_read_timeout_returns_fallback(self, mock_client_cls):
        """ReadTimeout should trigger fallback narrative."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = httpx.ReadTimeout(
            "Read timed out after 60s"
        )

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_pool_timeout_returns_fallback(self, mock_client_cls):
        """PoolTimeout should trigger fallback narrative."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = httpx.PoolTimeout(
            "Pool timeout after 5s"
        )

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    @pytest.mark.anyio
    @patch("sentinel.llm_service.httpx.AsyncClient")
    async def test_async_timeout_returns_empty_string(self, mock_client_cls):
        """async_generate_narrative returns '' on timeout (no fallback)."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = httpx.ReadTimeout("Read timed out")

        svc = _make_enabled_svc()
        result = await svc.async_generate_narrative(SAMPLE_CONTEXT)

        assert result == ""

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_timeout_does_not_crash_service(self, mock_client_cls):
        """Service should remain functional after timeout exceptions."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = httpx.ConnectTimeout("timeout")

        svc = _make_enabled_svc()

        # First call: timeout → fallback
        r1 = svc.generate_narrative(SAMPLE_CONTEXT)
        assert "Local Fallback" in r1

        # Second call: still works (no corrupted state)
        r2 = svc.generate_narrative(SAMPLE_CONTEXT)
        assert "Local Fallback" in r2


# ===========================================================================
# 3. Graceful Fallback on Ollama API Errors
# ===========================================================================

class TestGracefulFallback:
    """Integration tests for graceful fallback when Ollama throws errors."""

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_connection_refused_returns_fallback(self, mock_client_cls):
        """ConnectionRefused should trigger structured fallback."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = httpx.ConnectError("Connection refused")

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result
        assert "HIGH" in result

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_http_500_returns_fallback(self, mock_client_cls):
        """Ollama HTTP 500 should trigger fallback."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client.post.return_value = mock_response

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_http_503_returns_fallback(self, mock_client_cls):
        """Ollama HTTP 503 Service Unavailable should trigger fallback."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_client.post.return_value = mock_response

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_empty_ollama_response_triggers_fallback(self, mock_client_cls):
        """Empty response body from Ollama should trigger fallback."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": ""}
        mock_client.post.return_value = mock_response

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_json_decode_error_returns_fallback(self, mock_client_cls):
        """JSON decode error from Ollama should trigger fallback."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("err", "", 0)
        mock_client.post.return_value = mock_response

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_unexpected_exception_returns_fallback(self, mock_client_cls):
        """Unexpected RuntimeError should trigger fallback, not crash."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = RuntimeError("Unexpected failure")

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result

    def test_fallback_contains_all_context_fields(self):
        """Fallback narrative should embed key context fields."""
        svc = _make_disabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        assert "SSH_AUTH_FAILURE" in result
        assert "HIGH" in result
        assert "10.0.0.1" in result
        assert "2222" in result
        assert "TCP" in result
        assert "Brute Force" in result
        assert "T1110" in result
        assert "78.5%" in result

    def test_fallback_for_empty_context(self):
        """Fallback with empty context should use safe defaults."""
        svc = _make_disabled_svc()
        result = svc.generate_narrative({})

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result
        assert "Unknown Attack" in result

    def test_fallback_for_none_context(self):
        """Passing None context should still produce fallback gracefully."""
        svc = _make_disabled_svc()
        result = svc.generate_narrative(None)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result


# ===========================================================================
# 4. Mock Client Mode
# ===========================================================================

class TestMockClientMode:
    """Integration tests for SENTINEL_LLM_MOCK_CLIENT mode."""

    @pytest.mark.anyio
    async def test_mock_client_returns_mock_narrative(self):
        """When mock_client=True, _call_ollama returns MOCK_NARRATIVE_OUTPUT."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
            "SENTINEL_LLM_MOCK_CLIENT": "true",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()

        assert svc.mock_client is True
        result = await svc._call_ollama("test prompt")
        assert result == "MOCK_NARRATIVE_OUTPUT"

    @pytest.mark.anyio
    async def test_mock_client_no_http_call(self):
        """Mock client mode should not make any HTTP requests."""
        env = {
            "SENTINEL_LLM_ENABLED": "true",
            "SENTINEL_LLM_HOST": "http://localhost:11434",
            "SENTINEL_LLM_MODEL": "mistral",
            "SENTINEL_LLM_MOCK_CLIENT": "true",
        }
        with patch.dict(os.environ, env):
            svc = LLMService()

        with patch("sentinel.llm_service.httpx.AsyncClient") as mock_cls:
            await svc._call_ollama("prompt")
            mock_cls.assert_not_called()


# ===========================================================================
# 5. End-to-End Narrative Generation Pipeline
# ===========================================================================

class TestEndToEndPipeline:
    """Integration tests for full narrative generation workflows."""

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_successful_ollama_response(self, mock_client_cls):
        """Full pipeline: enabled → prompt → Ollama call → cleaned Markdown."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        raw_llm_text = (
            "## Threat Analysis\n\n"
            "A brute force attack was detected targeting SSH.\n\n\n\n\n"
            "### Mitigation\n"
            "Block the source IP immediately.   \n"
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": raw_llm_text}
        mock_client.post.return_value = mock_response

        svc = _make_enabled_svc()
        result = svc.generate_narrative(SAMPLE_CONTEXT)

        # Should return cleaned markdown, not fallback
        assert "Local Fallback" not in result
        assert "## Threat Analysis" in result
        assert "Block the source IP" in result
        # Markdown cleaning: collapsed blank lines
        assert "\n\n\n" not in result
        # Ends with single newline
        assert result.endswith("\n")
        assert not result.endswith("\n\n")

    @patch("sentinel.llm_service.httpx.AsyncClient")
    def test_prompt_contains_context_fields(self, mock_client_cls):
        """Verify the prompt sent to Ollama includes context data."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "narrative"}
        mock_client.post.return_value = mock_response

        svc = _make_enabled_svc()
        svc.generate_narrative(SAMPLE_CONTEXT)

        # Verify the POST payload
        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json")
        assert payload["model"] == "mistral"
        assert payload["stream"] is False
        assert len(payload["prompt"]) > 0

    @pytest.mark.anyio
    @patch("sentinel.llm_service.httpx.AsyncClient")
    async def test_async_successful_response(self, mock_client_cls):
        """async_generate_narrative returns cleaned LLM output."""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "Async AI narrative."}
        mock_client.post.return_value = mock_response

        svc = _make_enabled_svc()
        result = await svc.async_generate_narrative(SAMPLE_CONTEXT)

        assert result == "Async AI narrative.\n"

    @pytest.mark.anyio
    @patch("sentinel.llm_service.httpx.AsyncClient")
    async def test_async_empty_context_returns_empty(self, mock_client_cls):
        """async_generate_narrative with empty context returns ''."""
        svc = _make_enabled_svc()
        result = await svc.async_generate_narrative({})
        assert result == ""

    @pytest.mark.anyio
    @patch("sentinel.llm_service.httpx.AsyncClient")
    async def test_async_none_context_returns_empty(self, mock_client_cls):
        """async_generate_narrative with None context returns ''."""
        svc = _make_enabled_svc()
        result = await svc.async_generate_narrative(None)
        assert result == ""


# ===========================================================================
# 6. Markdown Post-Processing
# ===========================================================================

class TestMarkdownCleaning:
    """Integration tests for _clean_markdown pipeline."""

    def test_clean_empty_string(self):
        assert LLMService._clean_markdown("") == ""

    def test_clean_trailing_whitespace(self):
        result = LLMService._clean_markdown("line one   \nline two  \n")
        assert "   " not in result
        assert result == "line one\nline two\n"

    def test_clean_collapses_blank_lines(self):
        result = LLMService._clean_markdown("a\n\n\n\n\nb")
        assert result == "a\n\nb\n"

    def test_clean_adds_trailing_newline(self):
        result = LLMService._clean_markdown("no trailing newline")
        assert result.endswith("\n")

    def test_clean_preserves_valid_markdown(self):
        valid = "## Header\n\nParagraph text.\n\n- List item\n"
        result = LLMService._clean_markdown(valid)
        assert result == valid


# ===========================================================================
# 7. Module-level generate_playbook_summary Integration
# ===========================================================================

class TestGeneratePlaybookSummary:
    """Integration tests for the module-level generate_playbook_summary."""

    @pytest.mark.anyio
    @patch("sentinel.llm_service.httpx.AsyncClient")
    async def test_success_persists_narrative(self, mock_client_cls):
        """Successful LLM call persists narrative to playbook row."""
        mock_db = MagicMock(spec=Session)
        playbook = MockPlaybook()

        mock_db.query.return_value.filter.return_value.first.return_value = playbook

        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "LLM Summary"}
        mock_client.post.return_value = mock_response

        with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "true"}):
            result = await generate_playbook_summary(1, mock_db)

        assert result == "LLM Summary\n"
        assert playbook.llm_narrative == "LLM Summary\n"
        mock_db.commit.assert_called_once()

    @pytest.mark.anyio
    @patch("sentinel.llm_service.httpx.AsyncClient")
    async def test_ollama_error_uses_fallback(self, mock_client_cls):
        """Ollama error → fallback narrative still persisted."""
        mock_db = MagicMock(spec=Session)
        playbook = MockPlaybook()

        mock_db.query.return_value.filter.return_value.first.return_value = playbook

        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = Exception("Ollama down")

        with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "true"}):
            result = await generate_playbook_summary(1, mock_db)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result
        assert playbook.llm_narrative == result
        mock_db.commit.assert_called_once()

    @pytest.mark.anyio
    async def test_playbook_not_found_returns_empty(self):
        """Missing playbook ID returns empty string."""
        mock_db = MagicMock(spec=Session)
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = await generate_playbook_summary(999, mock_db)
        assert result == ""

    @pytest.mark.anyio
    @patch("sentinel.llm_service.httpx.AsyncClient")
    async def test_timeout_in_summary_uses_fallback(self, mock_client_cls):
        """Timeout during generate_playbook_summary uses fallback."""
        mock_db = MagicMock(spec=Session)
        playbook = MockPlaybook()
        mock_db.query.return_value.filter.return_value.first.return_value = playbook

        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.side_effect = httpx.ReadTimeout("Read timed out")

        with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "true"}):
            result = await generate_playbook_summary(1, mock_db)

        assert "Local Fallback" in result
        mock_db.commit.assert_called_once()


# ===========================================================================
# 8. Prompt Building Integration
# ===========================================================================

class TestPromptBuilding:
    """Integration tests for prompt construction pipeline."""

    def test_build_context_prompt_contains_attack_info(self):
        """_build_context_prompt should include all context fields."""
        svc = _make_disabled_svc()
        prompt = svc._build_context_prompt(SAMPLE_CONTEXT)

        assert len(prompt) > 100
        assert "cybersecurity" in prompt.lower() or "threat" in prompt.lower()

    def test_build_context_prompt_empty_context(self):
        """Empty context should still produce a valid prompt."""
        svc = _make_disabled_svc()
        prompt = svc._build_context_prompt({})
        assert len(prompt) > 50

    def test_legacy_build_prompt_with_playbook(self):
        """Module-level build_prompt embeds playbook fields."""
        pb = MockPlaybook()
        prompt = build_prompt(pb)

        assert "SSH Brute Force Mitigations" in prompt
        assert "T1021.004" in prompt
        assert "192.168.1.100" in prompt
        assert "Markdown" in prompt

    def test_legacy_fallback_narrative_with_playbook(self):
        """Module-level generate_fallback_narrative produces valid Markdown."""
        pb = MockPlaybook()
        result = generate_fallback_narrative(pb)

        assert "### AI-Powered Playbook Narrative (Local Fallback)" in result
        assert "192.168.1.100" in result
        assert "Containment" in result
