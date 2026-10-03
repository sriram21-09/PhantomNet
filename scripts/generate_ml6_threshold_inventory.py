#!/usr/bin/env python3
"""
ML-6: Threshold & Calibration Reference Inventory Generator
Scans repository for threshold, calibration, weight, and scoring occurrences.
Produces: experiments/results/ml6_threshold_reference_inventory.json
"""

import os
import sys
import json
import re
from typing import List, Dict, Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

TARGET_PATTERNS = {
    "0.80": re.compile(r"\b0\.80?\b"),
    "0.50": re.compile(r"\b0\.50?\b"),
    "0.60": re.compile(r"\b0\.60?\b"),
    "0.40": re.compile(r"\b0\.40?\b"),
    "RF_WEIGHT": re.compile(r"\bRF_WEIGHT\b"),
    "IF_WEIGHT": re.compile(r"\bIF_WEIGHT\b"),
    "calibration": re.compile(r"\bcalibration\b", re.IGNORECASE),
    "decision_function": re.compile(r"\bdecision_function\b"),
    "threshold": re.compile(r"\bthreshold\b", re.IGNORECASE),
    "BLOCK": re.compile(r"\bBLOCK\b"),
    "ALERT": re.compile(r"\bALERT\b"),
    "ALLOW": re.compile(r"\bALLOW\b"),
    "min-max": re.compile(r"\bmin-max\b", re.IGNORECASE),
    "s_min": re.compile(r"\bs_min\b"),
    "s_max": re.compile(r"\bs_max\b"),
    "predict_proba": re.compile(r"\bpredict_proba\b"),
    "ECE": re.compile(r"\bECE\b"),
    "Brier": re.compile(r"\bBrier\b", re.IGNORECASE),
    "calibration_curve": re.compile(r"\bcalibration_curve\b"),
    "isotonic": re.compile(r"\bisotonic\b", re.IGNORECASE),
    "Platt": re.compile(r"\bPlatt\b", re.IGNORECASE),
    "sigmoid": re.compile(r"\bsigmoid\b", re.IGNORECASE),
    "CalibratedClassifierCV": re.compile(r"\bCalibratedClassifierCV\b"),
}

EXTENSIONS = {".py", ".md", ".json", ".yaml", ".yml", ".sh", ".ps1"}
EXCLUDE_DIRS = {".git", ".system_generated", "venv", ".venv", "__pycache__", "node_modules", ".pytest_cache"}

def scan_repository():
    occurrences = []
    
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext not in EXTENSIONS:
                continue
            filepath = os.path.join(root, f)
            rel_path = os.path.relpath(filepath, PROJECT_ROOT).replace("\\", "/")
            
            # Avoid scanning the generated inventory itself or prompt file
            if rel_path in ["experiments/results/ml6_threshold_reference_inventory.json", "ml6_prompt.txt"]:
                continue
                
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    for line_idx, line in enumerate(fh, 1):
                        line_str = line.strip()
                        if not line_str:
                            continue
                        
                        # Match patterns
                        for term, regex in TARGET_PATTERNS.items():
                            if regex.search(line_str):
                                # Determine role and classification
                                is_doc = ext == ".md"
                                is_test = "test" in rel_path.lower()
                                is_backend_config = "backend/ml/config" in rel_path
                                is_backend_model = "backend/ml/models" in rel_path
                                is_production = is_backend_config or is_backend_model or ("backend" in rel_path and not is_test)
                                is_experiment = "experiment" in rel_path.lower() or "scripts" in rel_path.lower()
                                
                                role = "documentation" if is_doc else (
                                    "test" if is_test else (
                                        "production_core" if (is_backend_config or is_backend_model) else (
                                            "production_service" if is_production else (
                                                "experiment" if is_experiment else "other"
                                            )
                                        )
                                    )
                                )
                                
                                status = "active"
                                if "quarantine" in rel_path.lower():
                                    status = "quarantined"
                                elif "legacy" in rel_path.lower() or "archive" in rel_path.lower():
                                    status = "legacy"
                                elif is_experiment:
                                    status = "experimental"
                                
                                affects_scoring = (is_backend_config or is_backend_model or "threat_scoring_service" in rel_path) and not is_test
                                affects_eval = is_experiment or is_test
                                
                                occurrences.append({
                                    "file": rel_path,
                                    "line": line_idx,
                                    "matched_pattern": term,
                                    "line_snippet": line_str[:120],
                                    "role": role,
                                    "status": status,
                                    "affects_canonical_scoring": affects_scoring,
                                    "affects_experiment_evaluation": affects_eval,
                                    "is_documentation": is_doc
                                })
            except Exception as e:
                pass
                
    output_path = os.path.join(PROJECT_ROOT, "experiments", "results", "ml6_threshold_reference_inventory.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    inventory_summary = {
        "total_occurrences": len(occurrences),
        "patterns_tracked": list(TARGET_PATTERNS.keys()),
        "occurrences": occurrences
    }
    
    with open(output_path, "w", encoding="utf-8") as out_f:
        json.dump(inventory_summary, out_f, indent=2)
        
    print(f"Generated {output_path} with {len(occurrences)} occurrences.")

if __name__ == "__main__":
    scan_repository()
