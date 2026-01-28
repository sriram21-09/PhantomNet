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
    """
    Extract basic features from one event row
    """
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
    print("[*] Loading dataset...")
    df = pd.read_csv(CSV_PATH)

    print(f"[*] Total events loaded: {len(df)}")

    extracted = []
    latencies = []
    cpu_samples = []
    mem_samples = []

    process = psutil.Process(os.getpid())

    # Warm-up CPU measurement
    psutil.cpu_percent(interval=None)

    mem_start = get_memory_mb(process)

    print("[*] Starting feature extraction with performance monitoring...")

    for idx, row in df.iterrows():
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

    mem_end = get_memory_mb(process)

    # ======================
    # PERFORMANCE STATISTICS
    # ======================

    avg_latency = sum(latencies) / len(latencies)
    min_latency = min(latencies)
    max_latency = max(latencies)

    avg_cpu = sum(cpu_samples) / len(cpu_samples)
    peak_cpu = max(cpu_samples)

    peak_mem = max(mem_samples)

    print("\n--- Latency Statistics (ms) ---")
    print(f"Average latency : {avg_latency:.4f}")
    print(f"Minimum latency : {min_latency:.4f}")
    print(f"Maximum latency : {max_latency:.4f}")

    print("\n--- CPU Usage Statistics (%) ---")
    print(f"Average CPU usage : {avg_cpu:.2f}")
    print(f"Peak CPU usage    : {peak_cpu:.2f}")

    print("\n--- Memory Usage Statistics (MB) ---")
    print(f"Memory at start  : {mem_start:.2f}")
    print(f"Memory at end    : {mem_end:.2f}")
    print(f"Peak memory used : {peak_mem:.2f}")

    # ======================
    # FEATURE STATISTICS
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
    min_payload = min(payload_lengths) if payload_lengths else 0
    max_payload = max(payload_lengths) if payload_lengths else 0

    print("\n--- Feature Statistics ---")
    print(f"Total events           : {len(df)}")
    print(f"Unique honeypots       : {len(honeypot_counts)}")
    print(f"Missing payload (%)    : {(missing_payload / len(df)) * 100:.2f}%")
    print(f"Missing source IP (%)  : {(missing_ip / len(df)) * 100:.2f}%")
    print(f"Payload length (avg)   : {avg_payload:.2f}")
    print(f"Payload length (min)   : {min_payload}")
    print(f"Payload length (max)   : {max_payload}")

    print("\nHoneypot distribution:")
    for k, v in honeypot_counts.items():
        print(f"  {k}: {v}")

    print("\nEvent type distribution:")
    for k, v in event_type_counts.items():
        print(f"  {k}: {v}")

    # ======================
    # EXPORT TO JSON
    # ======================

    stats = {
        "dataset": {
            "total_events": len(df),
            "unique_honeypots": len(honeypot_counts)
        },
        "latency_ms": {
            "average": avg_latency,
            "minimum": min_latency,
            "maximum": max_latency
        },
        "cpu_usage_percent": {
            "average": avg_cpu,
            "peak": peak_cpu
        },
        "memory_usage_mb": {
            "start": mem_start,
            "end": mem_end,
            "peak": peak_mem
        },
        "data_quality": {
            "missing_payload_percent": (missing_payload / len(df)) * 100,
            "missing_source_ip_percent": (missing_ip / len(df)) * 100
        },
        "payload_length": {
            "average": avg_payload,
            "minimum": min_payload,
            "maximum": max_payload
        },
        "honeypot_distribution": dict(honeypot_counts),
        "event_type_distribution": dict(event_type_counts)
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=4)

    print(f"\n[*] Feature statistics exported to {OUTPUT_JSON}")
    print(f"[*] Total feature vectors extracted: {len(extracted)}")


if __name__ == "__main__":
    main()
