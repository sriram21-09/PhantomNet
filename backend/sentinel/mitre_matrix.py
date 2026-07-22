"""
backend/sentinel/mitre_matrix.py
---------------------------------
PhantomNet Sentinel Layer — MITRE ATT&CK Matrix Builder

Builds the aggregated MITRE ATT&CK heatmap payload consumed by the
``/api/sentinel/mitre/matrix`` endpoint and the frontend MitreMatrix component.

Public API
----------
  get_mitre_matrix_config() -> dict[tactic, list[technique]]
      Returns all known techniques grouped by tactic name.

  get_playbook_counts_by_technique(db) -> dict[technique_id, int]
      Queries the sentinel_playbooks table and returns live counts.

  get_aggregated_matrix_data(db) -> dict[tactic, list[technique]]
      Merges config + live counts into a tactic-keyed dict.

  build_matrix_response(db) -> dict
      Full structured response for the API endpoint, including:
        - status, generated_at, total_tactics, total_techniques
        - matrix: { tactic_name -> [technique_objects_with_counts] }
        - frequency_map: { base_technique_id -> aggregated_count }
          (base ID strips sub-technique suffix, e.g. T1110.001 -> T1110)

The ``frequency_map`` is the key addition that the frontend MitreMatrix
component consumes: it looks up techniques by base ID (T1110, T1046, etc.).
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import func
from sqlalchemy.orm import Session

from sentinel.mitre_mapper import _TECHNIQUE_MAP
from sentinel.models import SentinelPlaybook

logger = logging.getLogger("sentinel.mitre_matrix")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _base_technique_id(technique_id: str) -> str:
    """
    Return the parent technique ID by stripping any sub-technique suffix.

    Examples:
        "T1110.001" -> "T1110"
        "T1059.007" -> "T1059"
        "T1046"     -> "T1046"   (already a base ID — unchanged)
    """
    return technique_id.split(".")[0] if technique_id else technique_id


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_mitre_matrix_config() -> Dict[str, List[Dict[str, Any]]]:
    """
    Map all 12 techniques to their respective tactics.

    Returns a dictionary grouping unique techniques by their tactic name.
    Techniques that share the same ``technique_id`` (e.g. T1046 mapped by
    two different signatures) appear only once per tactic column.

    Returns:
        dict[str, list[dict]] — tactic name -> list of technique dicts.
    """
    matrix: Dict[str, List[Dict[str, Any]]] = {}
    for _sig, tech in _TECHNIQUE_MAP.items():
        tactic = tech["tactic"]
        if tactic not in matrix:
            matrix[tactic] = []

        # De-duplicate by technique_id within the same tactic column
        if not any(t["technique_id"] == tech["technique_id"] for t in matrix[tactic]):
            matrix[tactic].append({
                "technique_id":   tech["technique_id"],
                "technique_name": tech["technique_name"],
                "tactic_id":      tech.get("tactic_id"),
                "severity":       tech.get("severity"),
                "url":            tech.get("url"),
                "description":    tech.get("description"),
            })
    return matrix


def get_playbook_counts_by_technique(db: Session) -> Dict[str, int]:
    """
    Count playbooks grouped by MITRE ATT&CK technique ID.

    Only counts rows that have a non-null ``technique_id``.

    Args:
        db: SQLAlchemy database session.

    Returns:
        dict[str, int] — technique_id (exact, may be sub-technique) -> count.
    """
    results = (
        db.query(
            SentinelPlaybook.technique_id,
            func.count(SentinelPlaybook.id).label("cnt"),
        )
        .filter(SentinelPlaybook.technique_id.isnot(None))
        .group_by(SentinelPlaybook.technique_id)
        .all()
    )
    return {technique_id: cnt for technique_id, cnt in results}


def get_aggregated_matrix_data(db: Session) -> Dict[str, List[Dict[str, Any]]]:
    """
    Combine the static matrix configuration with live playbook counts.

    Attaches a ``count`` key to every technique entry reflecting how many
    playbooks reference that technique_id in the database.

    Args:
        db: SQLAlchemy database session.

    Returns:
        dict[str, list[dict]] — same structure as ``get_mitre_matrix_config()``
        but with ``count`` populated on every technique dict.
    """
    config = get_mitre_matrix_config()
    counts = get_playbook_counts_by_technique(db)

    for _tactic, techs in config.items():
        for tech in techs:
            tech["count"] = counts.get(tech["technique_id"], 0)

    return config


def build_matrix_response(db: Session) -> Dict[str, Any]:
    """
    Build the full structured API response for GET /api/sentinel/mitre/matrix.

    This is the canonical builder used by the endpoint.  It returns:

    {
      "status":           "success",
      "generated_at":     "<ISO-8601 UTC timestamp>",
      "total_tactics":    <int>,
      "total_techniques": <int>,
      "matrix": {
        "<Tactic Name>": [
          {
            "technique_id":   "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "tactic_id":      "TA0006",
            "severity":       "HIGH",
            "url":            "https://attack.mitre.org/...",
            "description":    "...",
            "count":          <int>   # live playbook count
          },
          ...
        ],
        ...
      },
      "frequency_map": {
        "T1110": <int>,   # base-ID → aggregated count (sum of sub-techniques)
        "T1046": <int>,
        ...
      }
    }

    The ``frequency_map`` is consumed directly by the MitreMatrix frontend
    component, which looks up techniques by their *base* ID (without the
    sub-technique suffix).

    Args:
        db: SQLAlchemy database session.

    Returns:
        Fully structured dict ready for JSON serialisation.
    """
    # ── 1. Build tactic-keyed matrix with live counts ─────────────────────
    matrix = get_aggregated_matrix_data(db)

    # ── 2. Build frequency_map keyed by base technique ID ─────────────────
    #    Aggregate per-technique counts upward to their parent base ID so the
    #    frontend can look up T1110 and receive the combined hit count for
    #    T1110.001 and T1110.004, etc.
    frequency_map: Dict[str, int] = {}
    total_unique_techniques: int = 0

    for _tactic, techs in matrix.items():
        for tech in techs:
            total_unique_techniques += 1
            base_id = _base_technique_id(tech["technique_id"])
            count = tech.get("count", 0)
            frequency_map[base_id] = frequency_map.get(base_id, 0) + count

    # ── 3. Assemble final response ─────────────────────────────────────────
    return {
        "status":           "success",
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "total_tactics":    len(matrix),
        "total_techniques": total_unique_techniques,
        "matrix":           matrix,
        "frequency_map":    frequency_map,
    }
