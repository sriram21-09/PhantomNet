import os
import sys
import time
import json
import hmac
import hashlib
import uuid
import psutil
import requests
import redis
import psycopg2
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parent.parent.parent

INGEST_URL = "http://localhost:8000/api/v1/ingest/event"
HONEYPOT_SECRET = "c3f7b19a82e44d01b8e8f3a921d74659b8a0e1c2d3e4f5a6b7c8d9e0f1a2b3c4"
HONEYPOT_ID = "ssh-honeypot-01"

# Thread-local session for connection pooling
import threading
thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=1)
        s = requests.Session()
        s.mount("http://", adapter)
        thread_local.session = s
    return thread_local.session

def send_event(idx: int):
    event_id = str(uuid.uuid4())
    ts_now = int(time.time())
    payload = {
        "event_id": event_id,
        "timestamp_ns": int(time.time() * 1e9),
        "honeypot_id": HONEYPOT_ID,
        "event_type": "ssh_login_attempt",
        "src_ip": f"198.51.100.{(idx % 250) + 1}",
        "src_port": 10000 + (idx % 50000),
        "dst_ip": "172.18.0.2",
        "dst_port": 2222,
        "protocol": "TCP",
        "payload": {"raw": f"SSH-2.0-OpenSSH_8.2p1 audit_load_event_{idx}", "session_id": f"sess_{idx % 100}"}
    }
    body_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(body_bytes).hexdigest()
    canonical_msg = f"{ts_now}:{digest}".encode("utf-8")
    sig = hmac.new(HONEYPOT_SECRET.encode("utf-8"), canonical_msg, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Honeypot-Signature": sig,
        "X-Honeypot-Timestamp": str(ts_now)
    }

    start = time.perf_counter()
    session = get_session()
    try:
        resp = session.post(INGEST_URL, data=body_bytes, headers=headers, timeout=5)
        latency_ms = (time.perf_counter() - start) * 1000
        return idx, event_id, resp.status_code, latency_ms, None
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        return idx, event_id, 0, latency_ms, str(e)

def get_redis_stream_len():
    try:
        r = redis.Redis(host="localhost", port=6379, db=0)
        return r.xlen("events:stream")
    except Exception as e:
        return -1

def get_postgres_packet_count():
    try:
        conn = psycopg2.connect(
            dbname="phantomnet",
            user="postgres",
            password="postgres",
            host="localhost",
            port=5432,
            connect_timeout=3
        )
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM packet_logs;")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        return count
    except Exception:
        return -1

def run_load_phase(target_eps: int, duration_sec: int, phase_name: str):
    total_events = target_eps * duration_sec
    print(f"[*] Starting {phase_name}: {target_eps} EPS for {duration_sec}s ({total_events} events)...")

    results = []
    latencies = []
    status_counts = {}
    telemetry_samples = []

    stream_len_before = get_redis_stream_len()
    pg_count_before = get_postgres_packet_count()

    start_time = time.perf_counter()
    interval = 1.0 / target_eps

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for i in range(total_events):
            scheduled_time = start_time + (i * interval)
            now = time.perf_counter()
            if scheduled_time > now:
                time.sleep(scheduled_time - now)

            futures.append(executor.submit(send_event, i))

            if i % target_eps == 0:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
                telemetry_samples.append({
                    "time_sec": round(time.perf_counter() - start_time, 2),
                    "cpu_percent": cpu,
                    "mem_percent": mem,
                    "submitted_so_far": i
                })

        for f in as_completed(futures):
            idx, event_id, status_code, latency_ms, err = f.result()
            results.append((event_id, status_code, latency_ms))
            latencies.append(latency_ms)
            status_counts[status_code] = status_counts.get(status_code, 0) + 1

    total_time = time.perf_counter() - start_time
    actual_throughput = len(results) / total_time if total_time > 0 else 0

    lat_arr = np.array(latencies) if latencies else np.array([0])
    p50 = float(np.percentile(lat_arr, 50))
    p95 = float(np.percentile(lat_arr, 95))
    p99 = float(np.percentile(lat_arr, 99))
    max_lat = float(np.max(lat_arr))
    mean_lat = float(np.mean(lat_arr))

    acknowledged = status_counts.get(202, 0)
    stream_len_after = get_redis_stream_len()
    pg_count_after = get_postgres_packet_count()

    summary = {
        "phase": phase_name,
        "target_eps": target_eps,
        "duration_sec": duration_sec,
        "total_submitted": total_events,
        "total_acknowledged_202": acknowledged,
        "event_loss": total_events - acknowledged,
        "status_distribution": status_counts,
        "actual_duration_sec": round(total_time, 2),
        "actual_throughput_eps": round(actual_throughput, 1),
        "latency_metrics_ms": {
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
            "mean": round(mean_lat, 2),
            "max": round(max_lat, 2)
        },
        "redis_stream_len_before": stream_len_before,
        "redis_stream_len_after": stream_len_after,
        "postgres_count_before": pg_count_before,
        "postgres_count_after": pg_count_after,
        "telemetry_samples": telemetry_samples
    }
    return summary

def execute_revalidation():
    print("[+] Starting Real Socket Ingestion Load Test (Remediation)...")

    # Phase 1: 500 EPS for 10 seconds
    res_500 = run_load_phase(500, 10, "500_EPS_SUSTAINED")

    # Phase 2: 1000 EPS for 5 seconds
    res_1000 = run_load_phase(1000, 5, "1000_EPS_BURST")

    combined = {
        "timestamp": datetime.utcnow().isoformat(),
        "target_url": INGEST_URL,
        "phases": [res_500, res_1000],
        "verdict": {
            "p99_under_100ms_500eps": res_500["latency_metrics_ms"]["p99"] < 100.0,
            "loss_under_500eps": res_500["event_loss"],
            "status_500eps": "PASS" if res_500["latency_metrics_ms"]["p99"] < 100.0 and res_500["event_loss"] == 0 else "FAIL",
            "status_1000eps": "PASS" if res_1000["event_loss"] == 0 else "DEGRADED"
        }
    }

    out_file = ROOT / "audit" / "remediation" / "load_test_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    with open(ROOT / "audit" / "remediation" / "perf_saturation_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.utcnow().isoformat(),
            "telemetry_500eps": res_500["telemetry_samples"],
            "telemetry_1000eps": res_1000["telemetry_samples"]
        }, f, indent=2)

    print(f"[+] Load test results written to {out_file}")
    print(f"    500 EPS: Acknowledged={res_500['total_acknowledged_202']}/{res_500['total_submitted']}, P99={res_500['latency_metrics_ms']['p99']}ms, Loss={res_500['event_loss']}")
    print(f"    1000 EPS: Acknowledged={res_1000['total_acknowledged_202']}/{res_1000['total_submitted']}, P99={res_1000['latency_metrics_ms']['p99']}ms, Loss={res_1000['event_loss']}")
    return combined

if __name__ == "__main__":
    execute_revalidation()
