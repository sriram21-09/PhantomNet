"""
backend/services/reconnect.py
-----------------------------
WebSocket Reconnection Algorithm with Full Jitter (RT-02).

Prevents thundering herd problems when many clients simultaneously attempt
reconnection after network partitions or service deployments.
Implements the canonical Full Jitter and Decorrelated Jitter algorithms
recommended by distributed systems research.
"""

from __future__ import annotations

import random
from typing import Dict, Any


def calculate_full_jitter_delay(
    attempt: int,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    random_seed: float | None = None,
) -> float:
    """
    Computes reconnection backoff with Full Jitter:
      temp = min(max_delay, base_delay * 2^attempt)
      delay = uniform(0, temp)

    Args:
        attempt: Zero-indexed reconnection attempt count.
        base_delay: Initial delay in seconds (default 1.0s).
        max_delay: Maximum delay cap in seconds (default 30.0s).
        random_seed: Optional pseudo-random multiplier in [0.0, 1.0] for deterministic testing.

    Returns:
        float: Backoff sleep interval in seconds.
    """
    attempt = max(0, attempt)
    # Exponential backoff upper bound
    temp = min(max_delay, base_delay * (2 ** attempt))
    
    if random_seed is not None:
        clamped_seed = max(0.0, min(1.0, random_seed))
        return round(clamped_seed * temp, 3)

    return round(random.uniform(0.0, temp), 3)


def calculate_decorrelated_jitter_delay(
    prev_delay: float,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> float:
    """
    Computes reconnection backoff with Decorrelated Jitter:
      delay = min(max_delay, uniform(base_delay, prev_delay * 3))
    """
    sleep = min(max_delay, random.uniform(base_delay, max(base_delay, prev_delay * 3.0)))
    return round(sleep, 3)


# JavaScript / TypeScript reference snippet for frontend client integration
FRONTEND_RECONNECT_SNIPPET = """
export function calculateFullJitterDelay(
  attempt: number,
  baseDelay: number = 1000,
  maxDelay: number = 30000
): number {
  const temp = Math.min(maxDelay, baseDelay * Math.pow(2, Math.max(0, attempt)));
  return Math.floor(Math.random() * temp);
}
"""
