import os
import sys
import time
import tracemalloc
import threading

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from ml.threat_scoring_service import score_threat_batch
from schemas.threat_schema import ThreatInput

def generate_random_inputs(num=1000):
    import random
    inputs = []
    protocols = ["TCP", "UDP", "ICMP"]
    for i in range(num):
        inputs.append(ThreatInput(
            src_ip=f"10.1.{random.randint(1, 254)}.{random.randint(1, 254)}",
            dst_ip=f"10.0.0.{random.randint(1, 254)}",
            dst_port=random.randint(20, 65535),
            protocol=random.choice(protocols),
            length=random.randint(40, 1500)
        ))
    return inputs

def worker(num_iterations, batch_size, error_array):
    try:
        for _ in range(num_iterations):
            batch = generate_random_inputs(batch_size)
            score_threat_batch(batch)
    except Exception as e:
        error_array.append(str(e))

def run_stress_test(duration_seconds=30, threads=5, batch_size=100):
    print(f"=== ML Pipeline Stress Testing ({duration_seconds}s) ===")
    
    tracemalloc.start()
    
    snapshot1 = tracemalloc.take_snapshot()
    
    start_time = time.time()
    iterations_per_thread = 50 # Start with fixed chunks
    
    metrics = {
        "errors": []
    }
    
    thread_pool = []
    print(f"Starting {threads} threads to hammer the ML scoring batch service...")
    
    while time.time() - start_time < duration_seconds:
        # Spawn threads
        for _ in range(threads):
            t = threading.Thread(target=worker, args=(iterations_per_thread, batch_size, metrics["errors"]))
            thread_pool.append(t)
            t.start()
            
        # Wait for this batch of threads
        for t in thread_pool:
            t.join()
            
        thread_pool.clear()
        
    snapshot2 = tracemalloc.take_snapshot()
    
    top_stats = snapshot2.compare_to(snapshot1, 'lineno')
    
    print("\n[Memory Profiling - Top 5 allocators]")
    for stat in top_stats[:5]:
        print(stat)
        
    # Simple heuristic to see if memory is exploding 
    # Compare total size 
    size1 = sum(stat.size for stat in snapshot1.statistics('lineno'))
    size2 = sum(stat.size for stat in snapshot2.statistics('lineno'))
    
    diff_mb = (size2 - size1) / (1024 * 1024)
    print(f"\nTotal Memory Growth over {duration_seconds}s: {diff_mb:.2f} MB")
    
    if diff_mb > 50:
        print("WARNING: High memory growth detected. Potential leak.")
    else:
        print("SUCCESS: Memory stability verified.")
        
    if metrics["errors"]:
        print(f"WARNING: Encountered {len(metrics['errors'])} exceptions during load!")
        for e in metrics["errors"][:3]:
            print(f"  - {e}")
    else:
        print("SUCCESS: No crashes or exceptions under load.")

if __name__ == "__main__":
    run_stress_test(duration_seconds=20) # Keep it short for CI/testing cycle
