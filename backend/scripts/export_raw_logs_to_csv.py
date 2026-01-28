print(">>> EXPORT SCRIPT STARTED <<<")

import json
import csv
import os
from datetime import datetime, timezone

# ======================
# PATH SETUP
# ======================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Go from backend/scripts → PhantomNet (project root)
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../.."))

LOG_DIR = os.path.join(PROJECT_ROOT, "backend", "logs")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")   # ✅ EXISTING data folder


print("[DEBUG] SCRIPT_DIR:", SCRIPT_DIR)
print("[DEBUG] PROJECT_ROOT:", PROJECT_ROOT)
print("[DEBUG] LOG_DIR:", LOG_DIR)
print("[DEBUG] DATA_DIR:", DATA_DIR)

# ======================
# LOG FILES
# ======================

LOG_FILES = [
    os.path.join(LOG_DIR, "ssh_async.jsonl"),
    os.path.join(LOG_DIR, "http_logs.jsonl"),
    os.path.join(LOG_DIR, "ftp_logs.jsonl"),
    os.path.join(LOG_DIR, "smtp_logs.jsonl")
]

print("[DEBUG] Checking log files:")
for f in LOG_FILES:
    print("   ", f, "exists ->", os.path.exists(f))

OUTPUT_CSV = os.path.join(DATA_DIR, "week6_test_events.csv")
MAX_EVENTS = 220

# ======================
# LOAD EVENTS
# ======================

events = []

for log_file in LOG_FILES:
    if not os.path.exists(log_file):
        continue

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except Exception:
                pass

print("[DEBUG] Total events loaded:", len(events))

# ======================
# TIMESTAMP NORMALIZATION
# ======================

def parse_time(event):
    ts = event.get("timestamp", "")
    try:
        ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)

        # Force UTC if naive
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)

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

        for event in latest_events:
            writer.writerow(event)

    print(f"[+] Exported {len(latest_events)} events to {OUTPUT_CSV}")
else:
    print("[WARN] No events to export")
