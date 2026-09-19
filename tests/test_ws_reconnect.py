import os
import sys
import pytest

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.services.reconnect import (
    calculate_full_jitter_delay,
    calculate_decorrelated_jitter_delay,
)


def test_exponential_backoff_upper_bound():
    """
    RT-02: Verify that the backoff upper bound grows exponentially
    and is strictly bounded by max_delay.
    """
    base = 1.0
    max_d = 30.0

    # Test deterministic ceiling (seed=1.0)
    ceiling_0 = calculate_full_jitter_delay(0, base_delay=base, max_delay=max_d, random_seed=1.0)
    ceiling_1 = calculate_full_jitter_delay(1, base_delay=base, max_delay=max_d, random_seed=1.0)
    ceiling_2 = calculate_full_jitter_delay(2, base_delay=base, max_delay=max_d, random_seed=1.0)
    ceiling_3 = calculate_full_jitter_delay(3, base_delay=base, max_delay=max_d, random_seed=1.0)
    ceiling_6 = calculate_full_jitter_delay(6, base_delay=base, max_delay=max_d, random_seed=1.0)

    assert ceiling_0 == 1.0
    assert ceiling_1 == 2.0
    assert ceiling_2 == 4.0
    assert ceiling_3 == 8.0
    # Capped by max_delay=30.0 (2^6 = 64 > 30)
    assert ceiling_6 == 30.0


def test_full_jitter_dispersion():
    """
    RT-02: Verify full jitter produces high variance across 100 simulated clients
    to effectively de-synchronize reconnection spikes (thundering herd prevention).
    """
    delays = [calculate_full_jitter_delay(attempt=4, base_delay=1.0, max_delay=30.0) for _ in range(100)]
    
    # All delays must be within [0, 16.0]
    for d in delays:
        assert 0.0 <= d <= 16.0

    # Variance must be non-zero and values distributed
    unique_values = set(delays)
    assert len(unique_values) > 75, "Full jitter must produce widely distributed reconnection times"


def test_decorrelated_jitter():
    """
    RT-02: Verify decorrelated jitter progresses within valid bounds.
    """
    delay = 1.0
    for _ in range(5):
        delay = calculate_decorrelated_jitter_delay(delay, base_delay=1.0, max_delay=30.0)
        assert 1.0 <= delay <= 30.0
