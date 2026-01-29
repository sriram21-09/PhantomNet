import pandas as pd
import time
import psutil
import os
import json
from collections import Counter

# ======================
# CONFIG
# ======================

CSV_PATH = "../../data/week6_test_events.csv"
OUTPUT_JSON = "../../data/feature_statistics.json"


# ======================
# MEMORY HELPER
# ======================

def get_memory_mb(process):
    return process.memory_info().rss / (1024 * 1024)


# ======================
# FEATURE EXTRACTION
# ======================

def extract_features(row):
    features = {}

    features["event_size"] = len(str(row.to_dict()))
    features["honeypot"] = row.get("honeypot_type") or row.get("honeypot")
    features["event_type"] = row.get("event")
    features["has_source_ip"] = bool(row.get("source_ip"))

    data_field = row.get("data")
    if pd.notna(data_field):
        features["payload_length"] = len(str(data_field))
    else:
        features["payload_length"] = 0

    return features


# ======================
# MAIN
# ======================

def main():
    # -------- DAY 4 (silent start) --------
    pipeline_start = time.perf_counter()
    failures = 0
    # -------------------------------------

    print("[*] Loading dataset...")
    df = pd.read_csv(CSV_PATH)

    print(f"[*] Total events loaded: {len(df)}")

    extracted = []
    latencies = []
    cpu_samples = []
    mem_samples = []

    process = psutil.Process(os.getpid())
    psutil.cpu_percent(interval=None)

    mem_start = get_memory_mb(process)

    print("[*] Starting feature extraction with performance monitoring...")

    for idx, row in df.iterrows():
        try:
            start = time.perf_counter()

            features = extract_features(row)
            extracted.append(features)

            end = time.perf_counter()
            latency_ms = (end - start) * 1000
            latencies.append(latency_ms)

            cpu_usage = psutil.cpu_percent(interval=None)
            cpu_samples.append(cpu_usage)

            mem_usage = get_memory_mb(process)
            mem_samples.append(mem_usage)

            if idx % 50 == 0:
                print(
                    f"    Processed {idx + 1} events | "
                    f"latency={latency_ms:.4f} ms | "
                    f"CPU={cpu_usage:.1f}% | "
                    f"MEM={mem_usage:.2f} MB"
                )
        except Exception:
            failures += 1

    mem_end = get_memory_mb(process)

    # ======================
    # OLD OUTPUT (UNCHANGED)
    # ======================

    print("\n--- Latency Statistics (ms) ---")
    print(f"Average latency : {sum(latencies)/len(latencies):.4f}")
    print(f"Minimum latency : {min(latencies):.4f}")
    print(f"Maximum latency : {max(latencies):.4f}")

    print("\n--- CPU Usage Statistics (%) ---")
    print(f"Average CPU usage : {sum(cpu_samples)/len(cpu_samples):.2f}")
    print(f"Peak CPU usage    : {max(cpu_samples):.2f}")

    print("\n--- Memory Usage Statistics (MB) ---")
    print(f"Memory at start  : {mem_start:.2f}")
    print(f"Memory at end    : {mem_end:.2f}")
    print(f"Peak memory used : {max(mem_samples):.2f}")

    # ======================
    # FEATURE STATISTICS (UNCHANGED)
    # ======================

    honeypot_counts = Counter()
    event_type_counts = Counter()
    payload_lengths = []
    missing_payload = 0
    missing_ip = 0

    for _, row in df.iterrows():
        honeypot = row.get("honeypot_type") or row.get("honeypot")
        event_type = row.get("event")

        honeypot_counts[honeypot] += 1
        event_type_counts[event_type] += 1

        data_field = row.get("data")
        if pd.notna(data_field):
            payload_lengths.append(len(str(data_field)))
        else:
            missing_payload += 1

        if not row.get("source_ip"):
            missing_ip += 1

    avg_payload = sum(payload_lengths) / len(payload_lengths) if payload_lengths else 0

    print("\n--- Feature Statistics ---")
    print(f"Total events           : {len(df)}")
    print(f"Unique honeypots       : {len(honeypot_counts)}")
    print(f"Missing payload (%)    : {(missing_payload / len(df)) * 100:.2f}%")
    print(f"Missing source IP (%)  : {(missing_ip / len(df)) * 100:.2f}%")
    print(f"Payload length (avg)   : {avg_payload:.2f}")
    print(f"Payload length (min)   : {min(payload_lengths)}")
    print(f"Payload length (max)   : {max(payload_lengths)}")

    print("\nHoneypot distribution:")
    for k, v in honeypot_counts.items():
        print(f"  {k}: {v}")

    print("\nEvent type distribution:")
    for k, v in event_type_counts.items():
        print(f"  {k}: {v}")

    # ======================
    # EXPORT (UNCHANGED)
    # ======================

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(
            {
                "total_events": len(df),
                "feature_vectors": len(extracted)
            },
            f,
            indent=4
        )

    print(f"\n[*] Feature statistics exported to {OUTPUT_JSON}")
    print(f"[*] Total feature vectors extracted: {len(extracted)}")

    # ======================
    # DAY 4 ADDITION (ONLY HERE)
    # ======================

    pipeline_end = time.perf_counter()
    total_pipeline_time_ms = (pipeline_end - pipeline_start) * 1000

    print("\n--- Day 4 Validation ---")
    print(f"Total pipeline time : {total_pipeline_time_ms:.2f} ms")
    print(f"Average per event   : {total_pipeline_time_ms / len(df):.4f} ms")
    print(f"Processing failures: {failures}")


if __name__ == "__main__":
    main()
