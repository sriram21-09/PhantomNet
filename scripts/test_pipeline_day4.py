import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import csv
from backend.ml.feature_extractor import FeatureExtractor
from backend.ml.anomaly_detector import AnomalyDetector
from backend.ml.threat_correlation import ThreatCorrelator

CSV_PATH = "week6_day4_pipeline_events.csv"

extractor = FeatureExtractor()
anomaly = AnomalyDetector()
correlator = ThreatCorrelator()

events = []

with open(CSV_PATH, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        # Normalize fields
        row["length"] = int(row["length"])
        row["threat_score"] = float(row["threat_score"])
        row["is_malicious"] = row["is_malicious"] == "t"
        events.append(row)

print(f"Loaded {len(events)} events\n")

# Train anomaly model on these events (Day 4 validation scope)
anomaly.train(events)

for i, event in enumerate(events, start=1):
    print(f"\nEvent {i}")

    features = extractor.extract_features(event)
    pred, score = anomaly.predict(event)
    threat = correlator.analyze_log(event)

    print(f"  Feature vector length: {len(features)}")
    print(f"  Anomaly prediction: {pred} | score: {round(score, 4)}")
    print(f"  Threat verdict: {threat['verdict']}")
    print(f"  Total risk score: {threat['total_risk_score']}")
