import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func

from sentinel.models import SentinelPlaybook
from sentinel.mitre_mapper import _TECHNIQUE_MAP

logger = logging.getLogger("sentinel.mitre_matrix")

def get_mitre_matrix_config() -> Dict[str, List[Dict[str, Any]]]:
    """
    Map all 12 techniques to their respective tactics.
    Returns a dictionary grouping techniques by their tactic name.
    """
    matrix = {}
    for sig, tech in _TECHNIQUE_MAP.items():
        tactic = tech["tactic"]
        if tactic not in matrix:
            matrix[tactic] = []
            
        # Avoid duplicate techniques if multiple signatures map to the same technique ID
        # e.g., T1046 is used by multiple signatures
        if not any(t["technique_id"] == tech["technique_id"] for t in matrix[tactic]):
            matrix[tactic].append({
                "technique_id": tech["technique_id"],
                "technique_name": tech["technique_name"],
                "tactic_id": tech.get("tactic_id"),
                "severity": tech.get("severity"),
                "url": tech.get("url"),
                "description": tech.get("description")
            })
    return matrix

def get_playbook_counts_by_technique(db: Session) -> Dict[str, int]:
    """
    Count playbooks grouped by MITRE ATT&CK technique ID.
    Returns a dictionary mapping technique_id to count.
    """
    results = (
        db.query(SentinelPlaybook.technique_id, func.count(SentinelPlaybook.id))
        .filter(SentinelPlaybook.technique_id.isnot(None))
        .group_by(SentinelPlaybook.technique_id)
        .all()
    )
    return {technique_id: count for technique_id, count in results}

def get_aggregated_matrix_data(db: Session) -> Dict[str, List[Dict[str, Any]]]:
    """
    Combines the structured matrix configuration with live playbook counts.
    Returns the final payload for the MitreMatrix UI component.
    """
    config = get_mitre_matrix_config()
    counts = get_playbook_counts_by_technique(db)
    
    for tactic, techs in config.items():
        for tech in techs:
            tech["count"] = counts.get(tech["technique_id"], 0)
            
    return config
