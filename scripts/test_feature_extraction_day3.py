"""
Feature Extraction Validation Script
-----------------------------------
Purpose:
- Validate FeatureExtractor output against real Week 6 events
- Debug feature behavior deterministically
- NO database writes
- NO model inference

Usage:
python scripts/test_feature_extraction_day3.py
"""

import sys
import os
import csv
from typing import Dict, List

# -------------------------------------------------------------------
# Path setup (explicit and predictable)
# -------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.ml.feature_extractor import FeatureExtractor


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def parse_bool(value: str) -> bool:
    """
    Parse common boolean string representations safely.
    """
    return value.strip().lower() in {"t", "true", "1", "yes"}


def load_events(csv_path: str) -> List[Dict]:
    """
    Load and normalize raw packet events from CSV.
    """
    events: List[Dict] = []

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            # Normalize expected fields defensively
            row["length"] = int(row.get("length", 0))
            row["threat_score"] = float(row.get("threat_score", 0.0))
            row["is_malicious"] = parse_bool(str(row.get("is_malicious", "false")))
            events.append(row)

    return events


def print_features(event_index: int, features: Dict) -> None:
    """
    Pretty-print extracted features for a single event.
    """
    print(f"\nEvent {event_index}")
    for name, value in features.items():
        print(f"  {name:<30} : {value}")


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main() -> None:
    # IMPORTANT:
    # This file MUST exist. Verified via filesystem scan.
    csv_path = os.path.join(
        PROJECT_ROOT,
        "data",
        "week6_test_events.csv"
    )

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Input file not found: {csv_path}")

    extractor = FeatureExtractor()
    events = load_events(csv_path)

    print(f"Loaded {len(events)} events")

    for idx, event in enumerate(events, start=1):
        features = extractor.extract_features(event)
        print_features(idx, features)


if __name__ == "__main__":
    main()
