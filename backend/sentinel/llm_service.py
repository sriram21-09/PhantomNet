"""
backend/sentinel/llm_service.py
--------------------------------
PhantomNet Sentinel Layer — LLM Service Module

Encapsulates all interactions with the Ollama inference engine and exposes
a clean class-based API for generating AI-enhanced narratives inside
incident playbooks.

Environment Variables
---------------------
SENTINEL_LLM_ENABLED : str  (default: "false")
    Master switch.  Set to ``"true"`` (case-insensitive) to enable LLM
    calls.  When disabled, ``generate_narrative()`` returns an empty string
    so callers can fall back to the local structured narrative.

SENTINEL_LLM_HOST : str  (default: "http://ollama:11434")
    Base URL of the Ollama inference server.  Supports both Docker-internal
    hostnames (``http://ollama:11434``) and local installs
    (``http://localhost:11434``).

SENTINEL_LLM_MODEL : str  (default: "mistral")
    Name of the model that has been ``ollama pull``-ed inside the Ollama
    container.

Public API
----------
LLMService
    Class-based interface.  Preferred entry point for new code.

    ``generate_narrative(context_data) -> str``
        Generate an AI narrative for the given context dict.
        Returns ``""`` when LLM is disabled or Ollama is unreachable.

    ``trigger_narrative(playbook_id)``
        Fire-and-forget: schedule narrative generation for a persisted
        SentinelPlaybook row (thread-safe, works inside and outside
        FastAPI's async event loop).

Module-level helpers (preserved for backward compatibility)
-----------------------------------------------------------
build_prompt(playbook) -> str
generate_fallback_narrative(playbook) -> str
generate_playbook_summary(playbook_id, db) -> Coroutine[str]
trigger_llm_summary(playbook_id) -> None

Week 17, Day 1 — LLM Service Scaffolding
Week 17, Day 2 — Structured Prompt Templates integration
Week 17, Day 3 — Async HTTP Client with 60-second timeout & Markdown post-processing
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Week 17, Day 2: structured prompt templates
try:
    from sentinel.prompt_templates import (
        build_narrative_prompt,
        render_narrative_prompt_jinja,
        normalise_utc_timestamp,
    )
    _PROMPT_TEMPLATES_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PROMPT_TEMPLATES_AVAILABLE = False
    normalise_utc_timestamp = None  # type: ignore[assignment]

import httpx
from httpx import Timeout as HttpxTimeout  # re-exported for convenience
from sqlalchemy.orm import Session

from database.database import SessionLocal
from sentinel.models import SentinelPlaybook

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("sentinel.llm_service")

# ---------------------------------------------------------------------------
# Module-level constants (read at import time so that the existing
# module-level helpers below keep working unchanged)
# ---------------------------------------------------------------------------
SENTINEL_LLM_ENABLED: bool = os.getenv("SENTINEL_LLM_ENABLED", "false").lower() == "true"
SENTINEL_LLM_HOST: str = os.getenv("SENTINEL_LLM_HOST", "http://ollama:11434")
SENTINEL_LLM_MODEL: str = os.getenv("SENTINEL_LLM_MODEL", "mistral")

# ---------------------------------------------------------------------------
# Week 17, Day 3: Strict timeout configuration for the async HTTP client
# ---------------------------------------------------------------------------
# Both connection establishment and read operations must complete within 60 s.
# Using httpx.Timeout to set connect and read independently so that a slow
# Ollama start-up or a large model response never blocks the application.
_OLLAMA_TIMEOUT = httpx.Timeout(
    connect=60.0,   # max seconds to establish the TCP connection
    read=60.0,      # max seconds to receive the full response body
    write=10.0,     # max seconds to send the request body
    pool=5.0,       # max seconds to acquire a connection from the pool
)


# ===========================================================================
# LLMService — class-based interface (Week 17, Day 1)
# ===========================================================================

class LLMService:
    """Encapsulates Ollama interactions and LLM-enabled state toggles.

    This class reads configuration from environment variables at instantiation
    time and exposes a clean, testable interface for generating AI-enhanced
    narratives inside Sentinel incident playbooks.

    Parameters
    ----------
    None — all configuration is loaded from environment variables.

    Attributes
    ----------
    enabled : bool
        ``True`` when ``SENTINEL_LLM_ENABLED=true`` (case-insensitive).
    host : str
        Base URL of the Ollama inference server (``SENTINEL_LLM_HOST``).
    model : str
        Ollama model name (``SENTINEL_LLM_MODEL``).

    Raises
    ------
    EnvironmentError
        If ``SENTINEL_LLM_ENABLED`` is ``"true"`` but ``SENTINEL_LLM_HOST``
        is empty or clearly malformed (missing scheme).

    Examples
    --------
    >>> svc = LLMService()
    >>> narrative = svc.generate_narrative({"attack_type": "SSH Brute Force",
    ...                                     "severity": "HIGH",
    ...                                     "src_ip": "10.0.0.1"})
    """

    # ------------------------------------------------------------------
    # Construction & configuration validation
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Dynamically check if LLM is enabled, checking database first, then environment."""
        if hasattr(self, "_enabled_override") and self._enabled_override is not None:
            return self._enabled_override

        try:
            from database.database import SessionLocal
            from database.models import SystemConfig
            db = SessionLocal()
            try:
                cfg = db.query(SystemConfig).filter(SystemConfig.key == "sentinel_llm_enabled").first()
                if cfg is not None:
                    return cfg.value.strip().lower() in ("1", "true", "yes", "on")
            finally:
                db.close()
        except Exception as e:
            pass
        
        return getattr(self, "_env_enabled", False)

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled_override = value

    def __init__(self) -> None:
        """Initialise LLMService from environment variables.

        Reads the three Sentinel LLM environment variables and validates
        the configuration when the service is enabled.
        """
        self._enabled_override = None
        raw_enabled = os.getenv("SENTINEL_LLM_ENABLED", "false").strip().lower()
        self._env_enabled = raw_enabled in ("1", "true", "yes", "on")

        self.host: str = os.getenv("SENTINEL_LLM_HOST", "http://ollama:11434").strip()
        self.model: str = os.getenv("SENTINEL_LLM_MODEL", "mistral").strip()
        self.mock_client: bool = os.getenv("SENTINEL_LLM_MOCK_CLIENT", "false").strip().lower() == "true"

        logger.info(
            "LLMService initialised | enabled=%s host=%s model=%s mock_client=%s",
            self.enabled, self.host, self.model, self.mock_client,
        )

        # Validate only when the service is enabled so that disabled
        # deployments require no Ollama configuration at all.
        if self.enabled:
            self._validate_config()

    def _validate_config(self) -> None:
        """Validate LLM configuration when the service is enabled.

        Checks:
        - ``SENTINEL_LLM_HOST`` is non-empty.
        - ``SENTINEL_LLM_HOST`` starts with ``http://`` or ``https://``.
        - ``SENTINEL_LLM_MODEL`` is non-empty.

        Raises
        ------
        EnvironmentError
            Descriptive message identifying which variable is misconfigured
            so operators can resolve it quickly.
        """
        if not self.host:
            raise EnvironmentError(
                "SENTINEL_LLM_ENABLED=true but SENTINEL_LLM_HOST is not set. "
                "Set SENTINEL_LLM_HOST to the Ollama base URL "
                "(e.g. http://ollama:11434 or http://localhost:11434)."
            )

        if not (self.host.startswith("http://") or self.host.startswith("https://")):
            raise EnvironmentError(
                f"SENTINEL_LLM_HOST={self.host!r} is invalid. "
                "The URL must start with 'http://' or 'https://'. "
                "Example: SENTINEL_LLM_HOST=http://ollama:11434"
            )

        if not self.model:
            raise EnvironmentError(
                "SENTINEL_LLM_ENABLED=true but SENTINEL_LLM_MODEL is not set. "
                "Set SENTINEL_LLM_MODEL to the Ollama model name "
                "(e.g. mistral, llama3, phi3)."
            )

        logger.info("LLMService configuration validated successfully.")

    # ------------------------------------------------------------------
    # Config introspection helper
    # ------------------------------------------------------------------

    def get_config(self) -> Dict[str, Any]:
        """Return a snapshot of the current LLM configuration.

        Useful for health-check endpoints and debug logging.

        Returns
        -------
        dict
            Keys: ``enabled``, ``host``, ``model``.
        """
        return {
            "enabled": self.enabled,
            "host": self.host,
            "model": self.model,
        }

    # ------------------------------------------------------------------
    # Core narrative generation (stub — async implementation)
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Week 17, Day 3: Markdown post-processing helper
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_markdown(text: str) -> str:
        """Normalise and clean the raw LLM response into valid Markdown.

        Applies the following transformations:
        - Strip leading/trailing whitespace from the full response.
        - Collapse sequences of 3+ blank lines down to 2 (standard Markdown
          paragraph separator).
        - Strip trailing whitespace from every individual line.
        - Ensure the document ends with a single newline.

        Parameters
        ----------
        text : str
            Raw response string returned by Ollama.

        Returns
        -------
        str
            Cleaned Markdown string ready for storage and display.
        """
        if not text:
            return ""
        # Strip trailing whitespace per line
        lines = [line.rstrip() for line in text.splitlines()]
        cleaned = "\n".join(lines).strip()
        # Collapse 3+ consecutive blank lines → 2
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        # Ensure single trailing newline
        return cleaned + "\n"

    # ------------------------------------------------------------------
    # Week 17, Day 3: Async HTTP client — strict 60-second timeout
    # ------------------------------------------------------------------

    async def _call_ollama(self, prompt: str, *, stream: bool = False) -> str:
        """Send a prompt to the Ollama ``/api/generate`` endpoint.

        Week 17, Day 3 changes
        ~~~~~~~~~~~~~~~~~~~~~~
        * Uses ``httpx.Timeout(connect=60, read=60)`` so neither the TCP
          handshake nor a slow model response can block the application
          indefinitely.
        * Supports **streaming** mode (``stream=True``): the NDJSON chunks
          emitted by Ollama are aggregated and joined locally so the caller
          always receives a single clean string.
        * All responses are post-processed through :meth:`_clean_markdown`
          before being returned.

        Parameters
        ----------
        prompt : str
            The full prompt string to send to the model.
        stream : bool
            When ``True``, uses Ollama's streaming NDJSON mode and aggregates
            the partial tokens.  Defaults to ``False`` (single JSON response).

        Returns
        -------
        str
            The model's response as clean Markdown text, or ``""`` on failure.
        """
        if getattr(self, "mock_client", False):
            logger.info("LLMService: using mock client, returning mock response.")
            return "MOCK_NARRATIVE_OUTPUT"

        url = f"{self.host}/api/generate"
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": stream,
        }

        try:
            async with httpx.AsyncClient(timeout=_OLLAMA_TIMEOUT) as client:
                if stream:
                    # ---- Streaming path: aggregate NDJSON chunks ----
                    collected_tokens: list[str] = []
                    async with client.stream("POST", url, json=payload) as response:
                        if response.status_code != 200:
                            logger.warning(
                                "LLMService._call_ollama (stream): Ollama returned "
                                "HTTP %d — skipping LLM narrative.",
                                response.status_code,
                            )
                            return ""
                        async for raw_line in response.aiter_lines():
                            raw_line = raw_line.strip()
                            if not raw_line:
                                continue
                            try:
                                chunk = json.loads(raw_line)
                            except json.JSONDecodeError:
                                logger.debug(
                                    "LLMService._call_ollama (stream): "
                                    "non-JSON line skipped: %r", raw_line
                                )
                                continue
                            token = chunk.get("response", "")
                            if token:
                                collected_tokens.append(token)
                            if chunk.get("done", False):
                                break

                    raw_text = "".join(collected_tokens)
                    logger.info(
                        "LLMService._call_ollama (stream): aggregated %d chars "
                        "from %d chunks (model=%s)",
                        len(raw_text), len(collected_tokens), self.model,
                    )

                else:
                    # ---- Aggregated (non-streaming) path ----
                    response = await client.post(url, json=payload)
                    if response.status_code != 200:
                        logger.warning(
                            "LLMService._call_ollama: Ollama returned HTTP %d "
                            "— skipping LLM narrative.",
                            response.status_code,
                        )
                        return ""
                    result = response.json()
                    raw_text = result.get("response", "")
                    logger.info(
                        "LLMService._call_ollama: received %d chars (model=%s)",
                        len(raw_text), self.model,
                    )

                clean_text = self._clean_markdown(raw_text)
                return clean_text

        except httpx.TimeoutException as exc:
            logger.warning(
                "LLMService._call_ollama: timeout after 60 s reaching Ollama "
                "at %s (stream=%s): %s",
                self.host, stream, exc,
            )
        except httpx.RequestError as exc:
            logger.warning(
                "LLMService._call_ollama: HTTP request error reaching Ollama "
                "at %s: %s",
                self.host, exc,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "LLMService._call_ollama: unexpected error: %s", exc
            )
        return ""

    def _build_context_prompt(self, context_data: Dict[str, Any]) -> str:
        """Build a structured prompt from a generic context dictionary.

        Week 17, Day 2: delegates to ``prompt_templates.build_narrative_prompt``
        when available, which produces the full 4-section structured prompt
        with UTC timestamp standardisation.  Falls back to the legacy
        inline prompt when the module is unavailable.

        The structured prompt includes:
        1. Campaign Cluster Metadata
        2. Source IPs / IOCs
        3. MITRE ATT&CK Mapping
        4. Mitigation Steps

        Parameters
        ----------
        context_data:
            Arbitrary dictionary of attack/campaign context values.
            Well-known keys (all optional):
            ``campaign_id``, ``event_count``, ``service_type``, ``protocol``,
            ``target_ports``, ``source_ips``, ``ioc_entries``,
            ``technique_id``, ``technique_name``, ``tactic``, ``mitre_url``,
            ``threat_score``, ``all_techniques``, ``confidence_score``,
            ``severity``, ``generated_at``, ``time_range_start``,
            ``time_range_end``.

        Returns
        -------
        str
            A fully structured Markdown prompt string ready for Ollama.
        """
        # --- Week 17 Day 2: use structured prompt templates module ---
        if _PROMPT_TEMPLATES_AVAILABLE:
            try:
                # Bridge legacy single-IP keys to structured multi-IP format
                enriched = dict(context_data)
                if "src_ip" in enriched and "source_ips" not in enriched:
                    enriched["source_ips"] = [enriched["src_ip"]]
                if "attack_type" in enriched and "service_type" not in enriched:
                    # Map attack_type to a plausible service_type
                    attack_map = {
                        "SSH_AUTH_FAILURE": "SSH",
                        "HTTP_SCANNER_BEHAVIOR": "HTTP",
                        "FTP_DATA_EXFILTRATION": "FTP",
                        "SMTP_LARGE_PAYLOAD": "SMTP",
                    }
                    enriched["service_type"] = attack_map.get(
                        str(enriched["attack_type"]).upper(), "UNKNOWN"
                    )
                if "generated_at" not in enriched:
                    enriched["generated_at"] = datetime.now(timezone.utc)

                prompt = render_narrative_prompt_jinja(enriched)
                logger.debug(
                    "_build_context_prompt: used structured Jinja2 prompt (%d chars)",
                    len(prompt),
                )
                return prompt
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "_build_context_prompt: structured prompt failed (%s) — "
                    "falling back to legacy prompt builder.", exc
                )

        # --- Legacy fallback (preserved for backward compatibility) ---
        known_keys = [
            ("attack_type",    "Attack Type"),
            ("severity",       "Severity"),
            ("src_ip",         "Source IP"),
            ("dst_port",       "Destination Port"),
            ("protocol",       "Protocol"),
            ("technique_id",   "MITRE Technique ID"),
            ("technique_name", "MITRE Technique Name"),
            ("tactic",         "Tactic"),
            ("threat_score",   "Threat Score"),
            ("event_count",    "Event Count"),
            ("campaign_id",    "Campaign ID"),
        ]

        lines: list[str] = [
            "You are a senior cybersecurity analyst. Analyse the following "
            "threat context and provide a concise, professional incident "
            "narrative (2-3 paragraphs). Format the output in Markdown.",
            "",
            "## Threat Context",
        ]

        rendered_keys: set[str] = set()
        for key, label in known_keys:
            value = context_data.get(key)
            if value is not None:
                lines.append(f"- **{label}**: {value}")
                rendered_keys.add(key)

        extras = {k: v for k, v in context_data.items() if k not in rendered_keys}
        if extras:
            lines.append("")
            lines.append("## Additional Context")
            for k, v in extras.items():
                lines.append(f"- **{k}**: {v}")

        lines.append("")
        lines.append(
            "Describe the threat activity, highlight key containment/mitigation "
            "steps, and keep the narrative professional and brief."
        )
        return "\n".join(lines)

    def _generate_fallback(self, context_data: Dict[str, Any]) -> str:
        """Generate a template-only fallback narrative from context data."""
        return (
            f"### AI-Powered Playbook Narrative (Local Fallback)\n\n"
            f"**Threat Analysis**\n"
            f"A **{context_data.get('severity', 'HIGH')}** severity security event has been "
            f"identified as **{context_data.get('attack_type', 'Unknown Attack')}** targeting "
            f"port **{context_data.get('dst_port', 'unknown')}** using the "
            f"**{context_data.get('protocol', 'TCP')}** protocol. This activity aligns with "
            f"MITRE ATT&CK technique "
            f"**{context_data.get('technique_name', 'Unknown Technique')} "
            f"({context_data.get('technique_id', 'T1000')})** under the "
            f"**{context_data.get('tactic', 'Unknown Tactic')}** tactic. The threat scoring "
            f"service assigned this event a confidence level of "
            f"**{context_data.get('threat_score', 0.0)}%**.\n\n"
            f"**Containment & Response Narrative**\n"
            f"1. **Source Isolation**: Immediately quarantine or block the attacker "
            f"source IP (**{context_data.get('src_ip', 'unknown')}**) at the perimeter "
            f"firewall to halt active probes.\n"
            f"2. **Alert Verification**: Inspect signature events and correlation "
            f"logs matching the target port **{context_data.get('dst_port', 'unknown')}** "
            f"for anomalies or lateral movement.\n"
            f"3. **Detection Validation**: Ensure IDS signatures, such as the Snort "
            f"rules defined in this playbook, are actively monitoring the relevant "
            f"network segment.\n"
            f"4. **Post-Incident Reporting**: Document all containment steps and "
            f"monitor the affected assets for persistent connection attempts.\n"
        )

    async def async_generate_narrative(
        self,
        context_data: Dict[str, Any],
        *,
        stream: bool = False,
    ) -> str:
        """Async coroutine — generate an AI-enhanced Markdown narrative.

        **Week 17, Day 3 primary deliverable.**  This is the preferred entry
        point for callers already running inside an ``async`` context (e.g.
        FastAPI route handlers, background tasks, or test coroutines).  It
        communicates with the dockerised Ollama API via the internal Docker
        network (``SENTINEL_LLM_HOST``) using ``httpx.AsyncClient`` with a
        strict 60-second connection and read timeout so the application is
        never blocked indefinitely.

        Parameters
        ----------
        context_data : dict
            Arbitrary key/value pairs describing the attack context.
            Recognised keys (all optional):

            - ``attack_type``    — Human-readable attack category
            - ``severity``       — Alert severity (HIGH, CRITICAL, …)
            - ``src_ip``         — Attacker source IP
            - ``dst_port``       — Target destination port
            - ``protocol``       — Network protocol (TCP, UDP, …)
            - ``technique_id``   — MITRE ATT&CK technique ID (e.g. T1110)
            - ``technique_name`` — MITRE technique display name
            - ``tactic``         — ATT&CK tactic (e.g. Credential Access)
            - ``threat_score``   — Numeric threat score (0–100)
            - ``event_count``    — Number of events in the campaign cluster
            - ``campaign_id``    — Campaign cluster identifier
            - ``source_ips``     — List of attacker IPs (structured prompt)
            - ``ioc_entries``    — List of IOC dicts (structured prompt)

        stream : bool
            When ``True``, uses Ollama's streaming NDJSON mode and aggregates
            partial tokens before returning.  Defaults to ``False``.

        Returns
        -------
        str
            AI-generated clean Markdown narrative, or ``""`` when:

            - ``SENTINEL_LLM_ENABLED`` is ``false``
            - Ollama is unreachable or returns a non-200 status
            - A timeout is exceeded (60 s connect or read)
            - Any unexpected exception occurs during generation
        """
        # --- Guard: service disabled ---
        if not self.enabled:
            logger.debug(
                "LLMService.async_generate_narrative: SENTINEL_LLM_ENABLED=false — "
                "returning empty string."
            )
            return ""

        # --- Validate context ---
        if not context_data or not isinstance(context_data, dict):
            logger.warning(
                "LLMService.async_generate_narrative: context_data is empty or "
                "not a dict — returning empty string."
            )
            return ""

        prompt = self._build_context_prompt(context_data)
        logger.info(
            "LLMService.async_generate_narrative: sending prompt to Ollama "
            "(%d chars, stream=%s, host=%s) …",
            len(prompt), stream, self.host,
        )

        narrative = await self._call_ollama(prompt, stream=stream)
        return narrative

    def generate_narrative(self, context_data: Dict[str, Any]) -> str:
        """Generate an AI-enhanced narrative for the given context data.

        Synchronous convenience wrapper around :meth:`async_generate_narrative`.
        When ``SENTINEL_LLM_ENABLED`` is ``false`` (default), it immediately
        returns a template-only fallback narrative.

        When enabled, it internally drives the async coroutine using the
        active event loop (FastAPI/Uvicorn) or a new event loop when running
        outside an async context.  Uses the strict 60-second timeout defined
        in ``_OLLAMA_TIMEOUT``.

        Parameters
        ----------
        context_data : dict
            Arbitrary key/value pairs describing the attack context.
            Recognised keys (all optional):

            - ``attack_type``    — Human-readable attack category
            - ``severity``       — Alert severity (HIGH, CRITICAL, …)
            - ``src_ip``         — Attacker source IP
            - ``dst_port``       — Target destination port
            - ``protocol``       — Network protocol (TCP, UDP, …)
            - ``technique_id``   — MITRE ATT&CK technique ID (e.g. T1110)
            - ``technique_name`` — MITRE technique display name
            - ``tactic``         — ATT&CK tactic (e.g. Credential Access)
            - ``threat_score``   — Numeric threat score (0–100)
            - ``event_count``    — Number of events in the campaign cluster
            - ``campaign_id``    — Campaign cluster identifier

        Returns
        -------
        str
            AI-generated Markdown narrative, or fallback template when:
            - ``SENTINEL_LLM_ENABLED`` is ``false``
            - Ollama is unreachable or returns a non-200 status
            - Any unexpected exception occurs during generation
        """
        # --- Guard: service disabled ---
        if not self.enabled:
            logger.warning(
                "LLMService.generate_narrative: SENTINEL_LLM_ENABLED=false — "
                "returning template-only fallback generation."
            )
            if not isinstance(context_data, dict):
                context_data = {}
            return self._generate_fallback(context_data)

        # --- Build prompt ---
        if not context_data or not isinstance(context_data, dict):
            logger.warning(
                "LLMService.generate_narrative: context_data is empty or not a dict — "
                "returning template-only fallback generation."
            )
            return self._generate_fallback({})

        prompt = self._build_context_prompt(context_data)
        logger.info(
            "LLMService.generate_narrative: sending prompt to Ollama (%d chars) …",
            len(prompt),
        )

        # --- Run async call synchronously ---
        try:
            # If inside an already-running event loop (FastAPI/Uvicorn)
            # schedule as a task and run until complete via run_coroutine_threadsafe.
            # The future timeout is set to 65 s (5 s grace above the 60-s read
            # timeout) so the thread never waits longer than necessary.
            try:
                loop = asyncio.get_running_loop()
                future = asyncio.run_coroutine_threadsafe(
                    self._call_ollama(prompt), loop
                )
                narrative = future.result(timeout=65)
            except RuntimeError:
                # No running event loop — safe to use asyncio.run()
                narrative = asyncio.run(self._call_ollama(prompt))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "LLMService.generate_narrative: unexpected error during Ollama call: %s",
                exc,
            )
            narrative = ""

        if not narrative:
            logger.warning("LLMService.generate_narrative: Using template-only fallback generation.")
            narrative = self._generate_fallback(context_data)

        return narrative

    # ------------------------------------------------------------------
    # Fire-and-forget wrapper for backward compatibility
    # ------------------------------------------------------------------

    def trigger_narrative(self, playbook_id: int) -> None:
        """Schedule LLM narrative generation for a persisted playbook row.

        Delegates to the module-level ``trigger_llm_summary()`` function so
        that existing callers (``sentinel_service.py``) do not need changes.

        Parameters
        ----------
        playbook_id : int
            Primary key of the ``SentinelPlaybook`` row to update.
        """
        trigger_llm_summary(playbook_id)


# ===========================================================================
# Module-level helpers — preserved for backward compatibility
# (test_llm_service.py imports these directly)
# ===========================================================================


def build_prompt(playbook: SentinelPlaybook) -> str:
    """Construct the prompt to send to the Ollama model.

    Parameters
    ----------
    playbook : SentinelPlaybook
        ORM object containing the playbook fields.

    Returns
    -------
    str
        Formatted prompt string ready for the Ollama ``/api/generate``
        endpoint.
    """
    return (
        f"Analyze the following cybersecurity playbook and provide a concise, "
        f"high-level summary of the threat and the response narrative for "
        f"security analysts.\n\n"
        f"Playbook Name: {playbook.playbook_name}\n"
        f"Attack Type: {playbook.attack_type}\n"
        f"MITRE ATT&CK Technique: {playbook.technique_name} ({playbook.technique_id})\n"
        f"Tactic: {playbook.tactic}\n"
        f"Severity: {playbook.severity}\n"
        f"Threat Score: {playbook.threat_score}\n"
        f"Source IP: {playbook.src_ip}\n"
        f"Destination Port: {playbook.dst_port}\n"
        f"Protocol: {playbook.protocol}\n\n"
        f"Please describe the threat activity, highlight key "
        f"containment/mitigation steps, and keep the description "
        f"professional and brief (2-3 paragraphs max). "
        f"Format the output in Markdown.\n"
    )


def generate_fallback_narrative(playbook: SentinelPlaybook) -> str:
    """Generate a structured local Markdown narrative when Ollama is offline.

    Parameters
    ----------
    playbook : SentinelPlaybook
        ORM object containing the playbook fields.

    Returns
    -------
    str
        High-quality local fallback narrative in Markdown format.
    """
    return (
        f"### AI-Powered Playbook Narrative (Local Fallback)\n\n"
        f"**Threat Analysis**\n"
        f"A **{playbook.severity or 'HIGH'}** severity security event has been "
        f"identified as **{playbook.attack_type or 'Unknown Attack'}** targeting "
        f"port **{playbook.dst_port or 'unknown'}** using the "
        f"**{playbook.protocol or 'TCP'}** protocol. This activity aligns with "
        f"MITRE ATT&CK technique "
        f"**{playbook.technique_name or 'Unknown Technique'} "
        f"({playbook.technique_id or 'T1000'})** under the "
        f"**{playbook.tactic or 'Unknown Tactic'}** tactic. The threat scoring "
        f"service assigned this event a confidence level of "
        f"**{playbook.threat_score or 0.0}%**.\n\n"
        f"**Containment & Response Narrative**\n"
        f"1. **Source Isolation**: Immediately quarantine or block the attacker "
        f"source IP (**{playbook.src_ip or 'unknown'}**) at the perimeter "
        f"firewall to halt active probes.\n"
        f"2. **Alert Verification**: Inspect signature events and correlation "
        f"logs matching the target port **{playbook.dst_port or 'unknown'}** "
        f"for anomalies or lateral movement.\n"
        f"3. **Detection Validation**: Ensure IDS signatures, such as the Snort "
        f"rules defined in this playbook, are actively monitoring the relevant "
        f"network segment.\n"
        f"4. **Post-Incident Reporting**: Document all containment steps and "
        f"monitor the affected assets for persistent connection attempts.\n"
    )


async def generate_playbook_summary(
    playbook_id: int, db: Optional[Session] = None
) -> str:
    """Generate an LLM-powered narrative summary for a given playbook.

    Queries the Ollama endpoint if available; falls back to a structured
    narrative if Ollama is offline or ``SENTINEL_LLM_ENABLED`` is false.

    Parameters
    ----------
    playbook_id : int
        Primary key of the ``SentinelPlaybook`` row.
    db : sqlalchemy.orm.Session, optional
        Active DB session.  When ``None`` a new session is created and
        closed automatically.

    Returns
    -------
    str
        Narrative Markdown string (LLM or local fallback).
    """
    local_session = False
    if db is None:
        db = SessionLocal()
        local_session = True

    try:
        playbook = (
            db.query(SentinelPlaybook)
            .filter(SentinelPlaybook.id == playbook_id)
            .first()
        )
        if not playbook:
            logger.error("Playbook with ID %d not found.", playbook_id)
            return ""

        prompt = build_prompt(playbook)
        narrative = ""

        # Attempt Ollama call when LLM is enabled (checking database first, then environment)
        llm_enabled = False
        try:
            from database.models import SystemConfig
            cfg = db.query(SystemConfig).filter(SystemConfig.key == "sentinel_llm_enabled").first()
            if cfg is not None:
                llm_enabled = cfg.value.strip().lower() in ("1", "true", "yes", "on")
            else:
                llm_enabled = (
                    os.getenv("SENTINEL_LLM_ENABLED", "false").strip().lower()
                    in ("1", "true", "yes", "on")
                )
        except Exception:
            llm_enabled = (
                os.getenv("SENTINEL_LLM_ENABLED", "false").strip().lower()
                in ("1", "true", "yes", "on")
            )
        if llm_enabled:
            try:
                # Week 17 Day 3: strict 60-second connect + read timeout
                async with httpx.AsyncClient(timeout=_OLLAMA_TIMEOUT) as client:
                    response = await client.post(
                        f"{SENTINEL_LLM_HOST}/api/generate",
                        json={
                            "model": SENTINEL_LLM_MODEL,
                            "prompt": prompt,
                            "stream": False,
                        },
                    )
                    if response.status_code == 200:
                        result = response.json()
                        raw_text = result.get("response", "")
                        # Apply clean Markdown post-processing
                        narrative = LLMService._clean_markdown(raw_text)
                        logger.info(
                            "Successfully generated LLM narrative using model %s "
                            "(%d chars after cleaning)",
                            SENTINEL_LLM_MODEL, len(narrative),
                        )
                    else:
                        logger.warning(
                            "Ollama API returned status %d. Using local fallback.",
                            response.status_code,
                        )
            except httpx.TimeoutException as exc:
                logger.warning(
                    "Ollama timeout (60 s) at %s: %s. Using local fallback.",
                    SENTINEL_LLM_HOST, exc,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to connect to Ollama endpoint at %s: %s. "
                    "Using local fallback.",
                    SENTINEL_LLM_HOST, exc,
                )
        else:
            logger.debug(
                "SENTINEL_LLM_ENABLED=false — skipping Ollama call for playbook %d.",
                playbook_id,
            )

        if not narrative:
            narrative = generate_fallback_narrative(playbook)

        # Persist narrative in the database
        playbook.llm_narrative = narrative
        playbook.updated_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("Updated playbook %d with narrative summary.", playbook_id)
        return narrative

    finally:
        if local_session:
            db.close()


def trigger_llm_summary(playbook_id: int) -> None:
    """Safely trigger LLM narrative summary generation in the background.

    Compatible with both async (FastAPI/Uvicorn) and sync/threaded contexts.
    Uses the active event loop when one is running; falls back to a daemon
    thread with ``asyncio.run()`` otherwise.

    Parameters
    ----------
    playbook_id : int
        Primary key of the ``SentinelPlaybook`` row to update.
    """
    try:
        loop = asyncio.get_running_loop()
        if loop.is_running():
            loop.create_task(generate_playbook_summary(playbook_id))
            logger.info(
                "Scheduled LLM narrative generation for playbook %d "
                "in active event loop.",
                playbook_id,
            )
            return
    except RuntimeError:
        pass  # No running loop — use thread fallback

    def _run_in_thread() -> None:
        asyncio.run(generate_playbook_summary(playbook_id))

    threading.Thread(target=_run_in_thread, daemon=True).start()
    logger.info(
        "Started background thread for LLM narrative generation of playbook %d.",
        playbook_id,
    )
