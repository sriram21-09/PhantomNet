import os
import httpx
import logging
import asyncio
from datetime import datetime
from sqlalchemy.orm import Session
from database.database import SessionLocal
from sentinel.models import SentinelPlaybook

logger = logging.getLogger("sentinel.llm_service")

SENTINEL_LLM_HOST = os.getenv("SENTINEL_LLM_HOST", "http://ollama:11434")
SENTINEL_LLM_MODEL = os.getenv("SENTINEL_LLM_MODEL", "mistral")


def build_prompt(playbook: SentinelPlaybook) -> str:
    """
    Constructs the prompt to send to the Ollama model.
    """
    return f"""Analyze the following cybersecurity playbook and provide a concise, high-level summary of the threat and the response narrative for security analysts.

Playbook Name: {playbook.playbook_name}
Attack Type: {playbook.attack_type}
MITRE ATT&CK Technique: {playbook.technique_name} ({playbook.technique_id})
Tactic: {playbook.tactic}
Severity: {playbook.severity}
Threat Score: {playbook.threat_score}
Source IP: {playbook.src_ip}
Destination Port: {playbook.dst_port}
Protocol: {playbook.protocol}

Please describe the threat activity, highlight key containment/mitigation steps, and keep the description professional and brief (2-3 paragraphs max). Format the output in Markdown.
"""


def generate_fallback_narrative(playbook: SentinelPlaybook) -> str:
    """
    Generates a high-quality local Markdown narrative fallback if the LLM service is offline or fails.
    """
    return f"""### AI-Powered Playbook Narrative (Local Fallback)

**Threat Analysis**
A **{playbook.severity or "HIGH"}** severity security event has been identified as **{playbook.attack_type or "Unknown Attack"}** targeting port **{playbook.dst_port or "unknown"}** using the **{playbook.protocol or "TCP"}** protocol. This activity aligns with MITRE ATT&CK technique **{playbook.technique_name or "Unknown Technique"} ({playbook.technique_id or "T1000"})** under the **{playbook.tactic or "Unknown Tactic"}** tactic. The threat scoring service assigned this event a confidence level of **{playbook.threat_score or 0.0}%**.

**Containment & Response Narrative**
1. **Source Isolation**: Immediately quarantine or block the attacker source IP (**{playbook.src_ip or "unknown"}**) at the perimeter firewall to halt active probes.
2. **Alert Verification**: Inspect signature events and correlation logs matching the target port **{playbook.dst_port or "unknown"}** for anomalies or lateral movement.
3. **Detection Validation**: Ensure IDS signatures, such as the Snort rules defined in this playbook, are actively monitoring the relevant network segment.
4. **Post-Incident Reporting**: Document all containment steps and monitor the affected assets for persistent connection attempts.
"""


async def generate_playbook_summary(playbook_id: int, db: Session = None) -> str:
    """
    Generates an LLM-powered narrative summary for a given playbook.
    Queries the Ollama endpoint if available, falling back to a structured narrative if offline.
    """
    local_session = False
    if db is None:
        db = SessionLocal()
        local_session = True

    try:
        playbook = db.query(SentinelPlaybook).filter(SentinelPlaybook.id == playbook_id).first()
        if not playbook:
            logger.error(f"Playbook with ID {playbook_id} not found.")
            return ""

        prompt = build_prompt(playbook)
        narrative = ""

        # Check if Ollama is accessible
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{SENTINEL_LLM_HOST}/api/generate",
                    json={
                        "model": SENTINEL_LLM_MODEL,
                        "prompt": prompt,
                        "stream": False
                    }
                )
                if response.status_code == 200:
                    result = response.json()
                    narrative = result.get("response", "").strip()
                    logger.info(f"Successfully generated LLM narrative using model {SENTINEL_LLM_MODEL}")
                else:
                    logger.warning(f"Ollama API returned status {response.status_code}. Using local fallback.")
        except Exception as e:
            logger.warning(f"Failed to connect to Ollama endpoint at {SENTINEL_LLM_HOST}: {e}. Using local fallback.")

        if not narrative:
            narrative = generate_fallback_narrative(playbook)

        # Update the database
        playbook.llm_narrative = narrative
        playbook.updated_at = datetime.utcnow()
        db.commit()
        logger.info(f"Updated playbook {playbook_id} with narrative summary.")
        return narrative
    finally:
        if local_session:
            db.close()


def trigger_llm_summary(playbook_id: int) -> None:
    """
    Safely triggers LLM narrative summary generation in the background,
    compatible with both async (FastAPI/Uvicorn) and sync/threaded contexts.
    """
    try:
        loop = asyncio.get_running_loop()
        if loop.is_running():
            loop.create_task(generate_playbook_summary(playbook_id))
            logger.info(f"Scheduled LLM narrative generation for playbook {playbook_id} in active event loop.")
            return
    except RuntimeError:
        pass

    # Thread-based fallback for sync callers
    import threading
    def run_in_thread():
        asyncio.run(generate_playbook_summary(playbook_id))

    threading.Thread(target=run_in_thread, daemon=True).start()
    logger.info(f"Started background thread for LLM narrative generation of playbook {playbook_id}.")
