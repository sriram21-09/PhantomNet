import os
import sys
import time
import pickle
import numpy as np
import pandas as pd
from memory_profiler import profile
from line_profiler import LineProfiler

# Setup paths
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import scoring functions
from ml.threat_scoring_service import score_threat, ThreatScorer
from schemas.threat_schema import ThreatInput

from services.threat_analyzer import threat_analyzer

print("Loading models for profiling...")

scorer = ThreatScorer()
scorer._load_model()
try:
    threat_analyzer._load_lstm()
except Exception as e:
    print(f"Failed to load LSTM: {e}")

# Generate 1000 dummy events for RF
print("Generating 1000 dummy inputs for Random Forest Profiling...")
rf_inputs = [
    ThreatInput(
        src_ip=f"192.168.1.{i%255}",
        dst_ip="10.0.0.1",
        src_port=10000 + i,
        dst_port=80,
        protocol="TCP",
        length=64,
    )
    for i in range(1000)
]

# Generate seq input chunks for LSTM
print("Generating sequences for LSTM Profiling...")
# lstm needs exactly 50 log dict approximations or PacketLogs to push through the buffer
from database.models import PacketLog
import datetime

base_time = datetime.datetime.now()
lstm_inputs = []
# Create 1000 logs all coming from the same IP to test the buffer logic 1000 times
for i in range(1000):
    lstm_inputs.append(
        PacketLog(
            id=i,
            src_ip="10.10.10.10",
            timestamp=base_time + datetime.timedelta(seconds=i),
            protocol="TCP",
            src_port=5000 + i,
            dst_port=22,
            length=100,
        )
    )


@profile
def profile_memory_rf():
    """Profile Memory usage of processing 1000 RF events."""
    for inp in rf_inputs:
        scorer.score(inp)


@profile
def profile_memory_lstm():
    """Profile Memory usage of processing 1000 LSTM events."""
    for log in lstm_inputs:
        threat_analyzer._compute_lstm_score("10.10.10.10", log)


def profile_time_rf():
    """Profile time for processing 1000 RF events."""
    start = time.time()
    for inp in rf_inputs:
        scorer.score(inp)
    dur = time.time() - start
    print(f"[RF] 1000 executions took {dur:.4f}s. Avg/event: {(dur/1000)*1000:.2f}ms")


def profile_time_lstm():
    """Profile time for processing 1000 LSTM sequence updates and inferencing."""
    start = time.time()
    for log in lstm_inputs:
        threat_analyzer._compute_lstm_score("10.10.10.10", log)
    dur = time.time() - start
    print(f"[LSTM] 1000 executions took {dur:.4f}s. Avg/event: {(dur/1000)*1000:.2f}ms")


def run_line_profiler():
    """Use LineProfiler to find bottlenecks inside the scorer."""
    lp = LineProfiler()
    lp_wrapper = lp(scorer.score)

    for inp in rf_inputs[:100]:  # Run 100 for line profiler
        lp_wrapper(inp)

    lp.print_stats()


if __name__ == "__main__":
    print("\n--- Time Profiling ---")
    profile_time_rf()
    profile_time_lstm()

    print("\n--- Memory Profiling ---")
    profile_memory_rf()
    profile_memory_lstm()

    print("\n--- Line Profiling (RF) ---")
    run_line_profiler()
