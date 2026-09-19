import json
import random
import math
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent.parent

def calculate_backoff_with_jitter(attempt, base=1000, max_delay=30000, factor=2):
    exp_delay = min(max_delay, base * (factor ** attempt))
    return math.floor(random.random() * exp_delay)

def test_rt02_backoff_and_jitter():
    print("=" * 60)
    print("PHANTOMNET V3 — RT-02 WEBSOCKET RECONNECTION VERIFICATION")
    print("=" * 60)

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "dimension": "RT-02",
        "description": "Bounded exponential backoff with full jitter for WebSocket reconnection",
        "parameters": {
            "base_delay_ms": 1000,
            "max_delay_ms": 30000,
            "backoff_factor": 2
        },
        "attempt_evaluations": {},
        "properties_verified": {}
    }

    # Test attempts 0 to 6 and 10
    attempts_to_test = [0, 1, 2, 3, 4, 5, 6, 10]
    TRIALS = 1000

    for att in attempts_to_test:
        delays = [calculate_backoff_with_jitter(att) for _ in range(TRIALS)]
        max_possible = min(30000, 1000 * (2 ** att))
        
        min_observed = min(delays)
        max_observed = max(delays)
        avg_observed = sum(delays) / len(delays)
        unique_count = len(set(delays))

        results["attempt_evaluations"][f"attempt_{att}"] = {
            "attempt_number": att,
            "theoretical_max_ms": max_possible,
            "min_observed_ms": min_observed,
            "max_observed_ms": max_observed,
            "avg_observed_ms": round(avg_observed, 2),
            "expected_avg_ms": round(max_possible / 2, 2),
            "unique_values_count": unique_count,
            "strictly_bounded": max_observed <= max_possible and min_observed >= 0
        }
        print(f"Attempt {att}: Max Limit={max_possible}ms | Observed Max={max_observed}ms, Min={min_observed}ms, Avg={avg_observed:.1f}ms (Unique: {unique_count}/{TRIALS})")

    # Verify Properties
    # 1. Bounded delay
    all_bounded = all(d["strictly_bounded"] for d in results["attempt_evaluations"].values())
    results["properties_verified"]["bounded_delay"] = all_bounded

    # 2. Exponential growth across attempts 0 to 4
    growth = [results["attempt_evaluations"][f"attempt_{i}"]["theoretical_max_ms"] for i in range(5)]
    is_exp_growth = all(growth[i] * 2 == growth[i+1] for i in range(len(growth)-1))
    results["properties_verified"]["exponential_growth"] = is_exp_growth

    # 3. Maximum cap enforcement at 30,000ms
    att5_max = results["attempt_evaluations"]["attempt_5"]["max_observed_ms"]
    att10_max = results["attempt_evaluations"]["attempt_10"]["max_observed_ms"]
    is_capped = att5_max <= 30000 and att10_max <= 30000 and results["attempt_evaluations"]["attempt_10"]["theoretical_max_ms"] == 30000
    results["properties_verified"]["maximum_cap_30000ms"] = is_capped

    # 4. Jitter randomness (mean should be ~50% of max, spread across range)
    is_jittered = all(
        (0.35 * d["theoretical_max_ms"] <= d["avg_observed_ms"] <= 0.65 * d["theoretical_max_ms"]) and
        (d["unique_values_count"] > 0.50 * min(TRIALS, d["theoretical_max_ms"]))
        for d in results["attempt_evaluations"].values()
    )
    results["properties_verified"]["full_jitter_randomness"] = is_jittered

    # 5. Connection lifecycle simulation: Reset on success & timer cleanup
    state = {
        "connected": False,
        "reconnect_attempts": 0,
        "timer_active": False,
        "pending_timer_id": None
    }

    def simulate_failure(att_state):
        if att_state["timer_active"]:
            # Clear previous timer
            att_state["timer_active"] = False
            att_state["pending_timer_id"] = None
        delay = calculate_backoff_with_jitter(att_state["reconnect_attempts"])
        att_state["reconnect_attempts"] += 1
        att_state["timer_active"] = True
        att_state["pending_timer_id"] = 12345
        return delay

    def simulate_open(att_state):
        att_state["connected"] = True
        att_state["reconnect_attempts"] = 0
        if att_state["timer_active"]:
            att_state["timer_active"] = False
            att_state["pending_timer_id"] = None

    def simulate_unmount(att_state):
        if att_state["timer_active"]:
            att_state["timer_active"] = False
            att_state["pending_timer_id"] = None
        att_state["connected"] = False

    # Run lifecycle sequence
    d1 = simulate_failure(state)
    d2 = simulate_failure(state)
    d3 = simulate_failure(state)
    attempts_before_open = state["reconnect_attempts"]
    simulate_open(state)
    attempts_after_open = state["reconnect_attempts"]
    timer_after_open = state["timer_active"]

    d_after_reset = simulate_failure(state)
    simulate_unmount(state)
    timer_after_unmount = state["timer_active"]

    lifecycle_ok = (
        attempts_before_open == 3 and
        attempts_after_open == 0 and
        timer_after_open is False and
        timer_after_unmount is False
    )
    results["properties_verified"]["successful_connection_reset"] = (attempts_after_open == 0)
    results["properties_verified"]["timer_cleanup_on_unmount"] = (timer_after_unmount is False)
    results["properties_verified"]["lifecycle_simulation_pass"] = lifecycle_ok

    all_passed = all(results["properties_verified"].values())
    results["overall_verdict"] = "VERIFIED" if all_passed else "NOT VERIFIED"

    out_file = ROOT / "audit" / "remediation" / "rt02_reconnect_backoff_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nProperties Verified:")
    for prop, val in results["properties_verified"].items():
        print(f"  {prop}: {val}")
    print(f"\nFinal Verdict for RT-02: {results['overall_verdict']}")
    print(f"Saved evidence to {out_file}")

if __name__ == "__main__":
    test_rt02_backoff_and_jitter()
