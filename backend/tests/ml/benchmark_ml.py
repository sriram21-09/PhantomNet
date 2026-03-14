import os
import sys
import time

# Add backend to sys path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from ml.threat_scoring_service import score_threat, score_threat_batch
from schemas.threat_schema import ThreatInput

def generate_random_inputs(num=1000):
    import random
    inputs = []
    protocols = ["TCP", "UDP", "ICMP"]
    for i in range(num):
        inputs.append(ThreatInput(
            src_ip=f"192.168.1.{random.randint(1, 254)}",
            dst_ip=f"10.0.0.{random.randint(1, 254)}",
            dst_port=random.randint(20, 65535),
            protocol=random.choice(protocols),
            length=random.randint(40, 1500)
        ))
    return inputs

def run_benchmarks():
    print("=== ML Pipeline Performance Benchmarking ===")
    
    # Pre-warm model load and cache
    inputs = generate_random_inputs(10)
    score_threat_batch(inputs)
    
    print("\n1. Single Event Latency Benchmark")
    single_inputs = generate_random_inputs(500)
    
    start_time = time.time()
    for inp in single_inputs:
        score_threat(inp)
    end_time = time.time()
    
    total_time_ms = (end_time - start_time) * 1000.0
    avg_latency_ms = total_time_ms / len(single_inputs)
    
    print(f"   Tested {len(single_inputs)} sequential events.")
    print(f"   Average Latency: {avg_latency_ms:.2f} ms per event")
    print(f"   Target: < 50ms per event -> {'PASS' if avg_latency_ms < 50 else 'FAIL'}")
    
    print("\n2. Batch Event Throughput Benchmark")
    batch_size = 100
    num_batches = 50
    total_events = batch_size * num_batches
    
    print(f"   Generating {total_events} events...")
    batches = [generate_random_inputs(batch_size) for _ in range(num_batches)]
    
    start_time = time.time()
    for batch in batches:
        score_threat_batch(batch)
    end_time = time.time()
    
    total_time_s = end_time - start_time
    eps = total_events / total_time_s
    
    print(f"   Processed {num_batches} batches of size {batch_size} ({total_events} total events).")
    print(f"   Throughput: {eps:.2f} EPS (Events Per Second)")
    print(f"   Target: > 1000 EPS -> {'PASS' if eps > 1000 else 'FAIL'}")
    
    # Save to standard output
    report_data = {
        "avg_latency_ms": avg_latency_ms,
        "throughput_eps": eps,
    }
    
if __name__ == "__main__":
    run_benchmarks()
