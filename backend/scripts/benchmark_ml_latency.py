import time
import statistics

from backend.ml.feature_extractor import FeatureExtractor
from backend.ml.anomaly_detector import AnomalyDetector
from backend.ml.threat_correlation import ThreatCorrelator

RUNS = 100

extractor = FeatureExtractor()
anomaly = AnomalyDetector()
correlator = ThreatCorrelator()

anomaly.load()

log_entry = {
    "src_ip": "192.168.1.10",
    "dst_ip": "10.0.0.5",
    "protocol": "TCP",
    "packet_length": 512,
    "timestamp": "2026-01-30T12:00:00"
}

latencies = []

print("⏱️ Running ML latency benchmark...")

for _ in range(RUNS):
    start = time.perf_counter()

    extractor.extract_features(log_entry)
    anomaly.predict(log_entry)
    correlator.analyze_log(log_entry)

    end = time.perf_counter()
    latencies.append((end - start) * 1000)

avg = statistics.mean(latencies)
p95 = statistics.quantiles(latencies, n=20)[18]
max_latency = max(latencies)

print("\n📊 Benchmark Results")
print(f"Runs: {RUNS}")
print(f"Average Latency: {avg:.2f} ms")
print(f"95th Percentile: {p95:.2f} ms")
print(f"Max Latency: {max_latency:.2f} ms")

if avg < 100:
    print("✅ PASS: Latency under 100 ms")
else:
    print("❌ FAIL: Latency exceeds 100 ms")
