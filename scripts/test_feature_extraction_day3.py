import sys
import os
import csv

# Ensure project root is in Python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from backend.ml.feature_extractor import FeatureExtractor

extractor = FeatureExtractor()
events = []

with open("week6_day3_events.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        row["length"] = int(row["length"])
        row["threat_score"] = float(row["threat_score"])
        row["is_malicious"] = row["is_malicious"] in ("t", "true", "True", "1")
        events.append(row)

print(f"Loaded {len(events)} events")

for i, event in enumerate(events, 1):
    features = extractor.extract_features(event)
    print(f"\nEvent {i}")
    for k, v in features.items():
        print(f"  {k}: {v}")
