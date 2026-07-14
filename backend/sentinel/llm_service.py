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
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
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
SENTINEL_LLM_HOST: str = os.getenv("SENTINEL_LLM_HOST", "http://ollama:11434")
SENTINEL_LLM_MODEL: str = os.getenv("SENTINEL_LLM_MODEL", "mistral")


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

    def __init__(self) -> None:
        """Initialise LLMService from environment variables.

        Reads the three Sentinel LLM environment variables and validates
        the configuration when the service is enabled.
        """
        raw_enabled: str = os.getenv("SENTINEL_LLM_ENABLED", "false").strip().lower()
        self.enabled: bool = raw_enabled in ("1", "true", "yes", "on")

        self.host: str = os.getenv("SENTINEL_LLM_HOST", "http://ollama:11434").strip()
        self.model: str = os.getenv("SENTINEL_LLM_MODEL", "mistral").strip()

        logger.info(
            "LLMService initialised | enabled=%s host=%s model=%s",
            self.enabled, self.host, self.model,
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

    async def _call_ollama(self, prompt: str) -> str:
        """Send a prompt to the Ollama ``/api/generate`` endpoint.

        Parameters
        ----------
        prompt:
            The full prompt string to send to the model.

        Returns
        -------
        str
            The model's response text, or ``""`` on failure.
        """
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.host}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                    },
                )
                if response.status_code == 200:
                    result = response.json()
                    text = result.get("response", "").strip()
                    logger.info(
                        "LLMService: Ollama response received (%d chars, model=%s)",
                        len(text), self.model,
                    )
                    return text
                else:
                    logger.warning(
                        "LLMService: Ollama returned HTTP %d — skipping LLM narrative.",
                        response.status_code,
                    )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "LLMService: Failed to reach Ollama at %s: %s",
                self.host, exc,
            )
        return ""

    def _build_context_prompt(self, context_data: Dict[str, Any]) -> str:
        """Build a prompt from a generic context dictionary.

        Constructs a concise, analyst-oriented prompt from arbitrary key/value
        pairs provided by the pipeline.  Unknown keys are appended as a
        supplementary data block so no information is silently dropped.

        Parameters
        ----------
        context_data:
            Arbitrary dictionary of attack/campaign context values.

        Returns
        -------
        str
            A formatted prompt string ready to send to Ollama.
        """
        # Well-known keys rendered with labels
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

        # Append any extra keys the caller provides
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

    def generate_narrative(self, context_data: Dict[str, Any]) -> str:
        """Generate an AI-enhanced narrative for the given context data.

        This is the primary public method of ``LLMService``.  When
        ``SENTINEL_LLM_ENABLED`` is ``false`` (default), it immediately
        returns an empty string so callers fall back to the local structured
        narrative without any network call.

        When enabled, it calls the Ollama ``/api/generate`` endpoint
        synchronously (running an event loop internally if none is active,
        or scheduling a coroutine in the active loop).

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
            AI-generated Markdown narrative, or ``""`` when:
            - ``SENTINEL_LLM_ENABLED`` is ``false``
            - Ollama is unreachable or returns a non-200 status
            - Any unexpected exception occurs during generation

        Notes
        -----
        This method is intentionally a **stub** with the full Ollama call
        wired in.  Callers that need async behaviour should call
        ``_call_ollama()`` directly inside an ``async`` context.
        """
        # --- Guard: service disabled ---
        if not self.enabled:
            logger.debug(
                "LLMService.generate_narrative: SENTINEL_LLM_ENABLED=false — "
                "returning empty string (callers should use fallback narrative)."
            )
            return ""

        # --- Build prompt ---
        if not context_data or not isinstance(context_data, dict):
            logger.warning(
                "LLMService.generate_narrative: context_data is empty or not a dict — "
                "returning empty string."
            )
            return ""

        prompt = self._build_context_prompt(context_data)
        logger.info(
            "LLMService.generate_narrative: sending prompt to Ollama (%d chars) …",
            len(prompt),
        )

        # --- Run async call synchronously ---
        try:
            # If inside an already-running event loop (FastAPI/Uvicorn)
            # schedule as a task and run until complete via run_coroutine_threadsafe
            try:
                loop = asyncio.get_running_loop()
                future = asyncio.run_coroutine_threadsafe(
                    self._call_ollama(prompt), loop
                )
                narrative = future.result(timeout=35)
            except RuntimeError:
                # No running event loop — safe to use asyncio.run()
                narrative = asyncio.run(self._call_ollama(prompt))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "LLMService.generate_narrative: unexpected error during Ollama call: %s",
                exc,
            )
            narrative = ""

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

        # Attempt Ollama call when LLM is enabled
        llm_enabled = (
            os.getenv("SENTINEL_LLM_ENABLED", "false").strip().lower()
            in ("1", "true", "yes", "on")
        )
        if llm_enabled:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
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
                        narrative = result.get("response", "").strip()
                        logger.info(
                            "Successfully generated LLM narrative using model %s",
                            SENTINEL_LLM_MODEL,
                        )
                    else:
                        logger.warning(
                            "Ollama API returned status %d. Using local fallback.",
                            response.status_code,
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
