"""
Training Dataset Regeneration Script
-----------------------------------
Purpose:
- Generate supervised ML dataset from Week 6 events
- Enforce FeatureExtractor contract (15 features)
- Derive correct binary labels for SOC ML

Output:
- data/training_dataset.csv
"""

import os
import sys
import csv
from typing import Dict, List

# --------------------------------------------------
# Path setup
# --------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.ml.feature_extractor import FeatureExtractor

# --------------------------------------------------
# Input / Output paths
# --------------------------------------------------

INPUT_EVENTS_CSV = os.path.join(PROJECT_ROOT, "data", "week6_mixed_events.csv")
OUTPUT_TRAINING_CSV = os.path.join(PROJECT_ROOT, "data", "training_dataset.csv")

# --------------------------------------------------
# Label logic (CRITICAL)
# --------------------------------------------------

def derive_label(event: Dict) -> int:
    """
    SOC-first label derivation.

    label = 1 (malicious) if:
      - is_malicious == True
      OR
      - attack_type is non-benign
      OR
      - threat_score >= 0.7
    """
    if str(event.get("is_malicious", "")).lower() in {"true", "t", "1", "yes"}:
        return 1

    attack_type = event.get("attack_type")
    if attack_type and attack_type.upper() not in {"BENIGN", "NORMAL"}:
        return 1

    try:
        if float(event.get("threat_score", 0.0)) >= 0.7:
            return 1
    except ValueError:
        pass

    return 0


# --------------------------------------------------
# Load raw events
# --------------------------------------------------

def load_events(path: str) -> List[Dict]:
    events = []

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Normalize types
            row["length"] = int(row.get("length", 0))
            row["threat_score"] = float(row.get("threat_score", 0.0))
            row["is_malicious"] = str(row.get("is_malicious", "false")).lower() in {
                "true", "t", "1", "yes"
            }
            events.append(row)

    return events


# --------------------------------------------------
# Main
# --------------------------------------------------

def main() -> None:
    if not os.path.exists(INPUT_EVENTS_CSV):
        raise FileNotFoundError(f"Input events file not found: {INPUT_EVENTS_CSV}")

    extractor = FeatureExtractor()
    events = load_events(INPUT_EVENTS_CSV)

    rows = []

    for event in events:
        features = extractor.extract_features(event)
        label = derive_label(event)

        row = {**features, "label": label}
        rows.append(row)

    # Write CSV
    with open(OUTPUT_TRAINING_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=FeatureExtractor.FEATURE_NAMES + ["label"]
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Training dataset regenerated: {OUTPUT_TRAINING_CSV}")
    print(f"Rows: {len(rows)}")
    print("Columns:")
    print(FeatureExtractor.FEATURE_NAMES + ['label'])


if __name__ == "__main__":
    main()
