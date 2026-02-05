#!/usr/bin/env python3

print(">>> EXPORT SCRIPT STARTED <<<")

import json
import csv
import os
from datetime import datetime, timezone

# ======================
# PATH SETUP
# ======================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# backend/scripts → project root
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../.."))

LOG_DIR = os.path.join(PROJECT_ROOT, "backend", "logs")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

print("[DEBUG] SCRIPT_DIR:", SCRIPT_DIR)
print("[DEBUG] PROJECT_ROOT:", PROJECT_ROOT)
print("[DEBUG] LOG_DIR:", LOG_DIR)
print("[DEBUG] DATA_DIR:", DATA_DIR)

# ======================
# LOG FILES (SOURCE → TYPE)
# ======================

LOG_SOURCES = {
    "ssh": os.path.join(LOG_DIR, "ssh_async.jsonl"),
    "http": os.path.join(LOG_DIR, "http_logs.jsonl"),
    "ftp": os.path.join(LOG_DIR, "ftp_logs.jsonl"),
    "smtp": os.path.join(LOG_DIR, "smtp_logs.jsonl"),
}

print("[DEBUG] Checking log files:")
for src, path in LOG_SOURCES.items():
    print(f"   {path} exists -> {os.path.exists(path)}")

OUTPUT_CSV = os.path.join(DATA_DIR, "week6_test_events.csv")
MAX_EVENTS = 220

# ======================
# ATTACK ENRICHMENT (CRITICAL)
# ======================

def enrich_attack_fields(event: dict, source: str) -> dict:
    """
    Assign SOC semantics based on honeypot source.
    """
    if source == "ssh":
        event["attack_type"] = "SSH_BRUTE_FORCE"
        event["is_malicious"] = True
        event["threat_score"] = 0.9

    elif source == "http":
        event["attack_type"] = "SQL_INJECTION"
        event["is_malicious"] = True
        event["threat_score"] = 0.8

    elif source == "ftp":
        event["attack_type"] = "FTP_RECON"
        event["is_malicious"] = True
        event["threat_score"] = 0.6

    elif source == "smtp":
        event["attack_type"] = "SMTP_SPOOF"
        event["is_malicious"] = True
        event["threat_score"] = 0.7

    else:
        event.setdefault("attack_type", "BENIGN")
        event.setdefault("is_malicious", False)
        event.setdefault("threat_score", 0.0)

    return event

# ======================
# TIMESTAMP NORMALIZATION
# ======================

def parse_time(event):
    ts = event.get("timestamp", "")
    try:
        ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)

# ======================
# LOAD & ENRICH EVENTS
# ======================

events = []

for source, log_file in LOG_SOURCES.items():
    if not os.path.exists(log_file):
        continue

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                event = enrich_attack_fields(event, source)
                events.append(event)
            except Exception:
                continue

print("[DEBUG] Total events loaded:", len(events))

# ======================
# SORT & SLICE
# ======================

events.sort(key=parse_time, reverse=True)
latest_events = events[:MAX_EVENTS]

print("[DEBUG] Events selected for CSV:", len(latest_events))

# ======================
# WRITE CSV
# ======================

os.makedirs(DATA_DIR, exist_ok=True)

if latest_events:
    fieldnames = set()
    for e in latest_events:
        fieldnames.update(e.keys())

    fieldnames = list(fieldnames)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(latest_events)

    print(f"[+] Exported {len(latest_events)} events to {OUTPUT_CSV}")
else:
    print("[WARN] No events to export")
