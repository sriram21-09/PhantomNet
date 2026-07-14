"""
backend/sentinel/__init__.py
----------------------------
PhantomNet Sentinel Layer — Package Root

This package implements the Sentinel threat intelligence pipeline:

  - mitre_mapper.py         : Maps attack types to MITRE ATT&CK techniques
  - rule_generator.py       : Generates Snort / Sigma detection rules
  - playbook_generator.py   : Renders Jinja2 response playbooks
  - stix_enhanced.py        : Produces enriched STIX 2.1 bundles
  - sentinel_service.py     : Orchestration service (Day 5 — Issue #673)
                              Populates PacketLog.detected_signatures by
                              inferring service type from dst_port and
                              querying the events table for raw payloads.
  - llm_service.py          : LLM Service Module (Week 17, Day 1)
                              Encapsulates Ollama interactions and state
                              toggles via SENTINEL_LLM_ENABLED /
                              SENTINEL_LLM_HOST environment variables.
                              Exposes LLMService class with
                              generate_narrative(context_data) -> str.

Sub-packages
------------
  templates/                : Jinja2 playbook templates (.j2 files)

⚠️  Population of PacketLog.detected_signatures is handled exclusively
    by sentinel_service.py — do NOT write signature logic elsewhere.
"""

# Package version — kept in sync with backend/main.py app version
__version__ = "3.0.0-sentinel"
