"""
backend/sentinel/confidence_scoring.py
----------------------------------------
PhantomNet Sentinel Layer — Playbook Confidence Scoring Engine

Calculates a composite confidence score (0.0–1.0) for a detected campaign
cluster using four weighted component signals:

  1. cluster_size_score  — normalised event count (more events → more certain)
  2. ml_avg_score        — average ML anomaly/threat score across cluster events
  3. ioc_density         — ratio of unique IOC IPs to total events
  4. multi_proto_bonus   — bonus when the campaign spans multiple protocols


Weighted Average Formula
------------------------
  confidence = (
      w_cluster  * cluster_size_score
    + w_ml       * ml_avg_score
    + w_ioc      * ioc_density
    + w_multi    * multi_proto_bonus
  )

Default weights (sum to 1.0):
  w_cluster  = 0.35   (biggest weight — cluster size is strong evidence)
  w_ml       = 0.35   (ML score is highly reliable when available)
  w_ioc      = 0.20   (IOC density is corroborating evidence)
  w_multi    = 0.10   (multi-protocol campaigns are more sophisticated)

Severity Mapping
----------------
  confidence >= 0.80  →  CRITICAL
  confidence >= 0.60  →  HIGH
  confidence >= 0.40  →  MEDIUM
  confidence <  0.40  →  LOW

Public API
----------
  calculate_confidence(
      event_count,
      ml_scores,
      unique_ioc_count,
      protocols,
      cluster_size_cap=200,
      weights=None,
  ) -> ConfidenceResult

  confidence_to_severity(confidence: float) -> str

  ConfidenceResult  (NamedTuple)
      confidence      : float   (0.0–1.0, clamped)
      severity        : str     (CRITICAL | HIGH | MEDIUM | LOW)
      cluster_size_score : float
      ml_avg_score    : float
      ioc_density     : float
      multi_proto_bonus: float
      breakdown       : dict    (all components for logging/debugging)
"""

from __future__ import annotations

import logging
from typing import Dict, List, NamedTuple, Optional, Sequence

logger = logging.getLogger("sentinel.confidence_scoring")

# ---------------------------------------------------------------------------
# Default weight configuration
# ---------------------------------------------------------------------------
DEFAULT_WEIGHTS: Dict[str, float] = {
    "cluster_size": 0.35,
    "ml_avg":       0.35,
    "ioc_density":  0.20,
    "multi_proto":  0.10,
}

# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------
_SEVERITY_THRESHOLDS = [
    (0.80, "CRITICAL"),
    (0.60, "HIGH"),
    (0.40, "MEDIUM"),
    (0.00, "LOW"),
]


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
class ConfidenceResult(NamedTuple):
    """
    Immutable result produced by ``calculate_confidence()``.

    Attributes
    ----------
    confidence : float
        Final composite confidence score clamped to [0.0, 1.0].
    severity : str
        Severity tier derived from confidence: CRITICAL | HIGH | MEDIUM | LOW.
    cluster_size_score : float
        Normalised cluster event count component [0.0, 1.0].
    ml_avg_score : float
        Normalised ML anomaly score component [0.0, 1.0].
    ioc_density : float
        IOC density component [0.0, 1.0].
    multi_proto_bonus : float
        Multi-protocol bonus component: 1.0 if multi-protocol else 0.0.
    breakdown : dict
        Full component-level detail for logging and API responses.
    """

    confidence:          float
    severity:            str
    cluster_size_score:  float
    ml_avg_score:        float
    ioc_density:         float
    multi_proto_bonus:   float
    breakdown:           dict


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def confidence_to_severity(confidence: float) -> str:
    """
    Map a confidence score (0.0–1.0) to a severity tier string.

    Args:
        confidence: Composite score, expected in [0.0, 1.0].

    Returns:
        ``"CRITICAL"`` | ``"HIGH"`` | ``"MEDIUM"`` | ``"LOW"``

    Examples
    --------
    >>> confidence_to_severity(0.95)
    'CRITICAL'
    >>> confidence_to_severity(0.75)
    'HIGH'
    >>> confidence_to_severity(0.55)
    'HIGH'
    >>> confidence_to_severity(0.45)
    'MEDIUM'
    >>> confidence_to_severity(0.20)
    'LOW'
    """
    clamped = max(0.0, min(1.0, confidence))
    for threshold, label in _SEVERITY_THRESHOLDS:
        if clamped >= threshold:
            return label
    return "LOW"  # fallback (unreachable with current thresholds)


def _normalise_cluster_size(event_count: int, cap: int = 200) -> float:
    """
    Normalise raw event count to [0.0, 1.0] using a linear cap.

    Events at or above ``cap`` score 1.0.  Zero events score 0.0.

    Args:
        event_count: Number of events in the cluster.
        cap:         Saturation point (default 200 events → score 1.0).

    Returns:
        Float in [0.0, 1.0].

    Examples
    --------
    >>> _normalise_cluster_size(0)
    0.0
    >>> _normalise_cluster_size(100, cap=200)
    0.5
    >>> _normalise_cluster_size(200, cap=200)
    1.0
    >>> _normalise_cluster_size(999, cap=200)
    1.0
    """
    if cap <= 0:
        cap = 200
    if event_count <= 0:
        return 0.0
    return min(1.0, event_count / cap)


def _normalise_ml_scores(ml_scores: Sequence[float]) -> float:
    """
    Average a list of ML anomaly scores and normalise to [0.0, 1.0].

    Scores are assumed to be in the range 0–100 (PacketLog.threat_score
    convention).  Values outside this range are clamped before averaging.

    Args:
        ml_scores: Iterable of float anomaly/threat scores (0–100 scale).

    Returns:
        Float in [0.0, 1.0].  Returns 0.0 when the list is empty.

    Examples
    --------
    >>> _normalise_ml_scores([])
    0.0
    >>> _normalise_ml_scores([50.0])
    0.5
    >>> _normalise_ml_scores([80.0, 100.0])
    0.9
    >>> _normalise_ml_scores([0.0, 0.0])
    0.0
    """
    if not ml_scores:
        return 0.0
    valid = [max(0.0, min(100.0, float(s))) for s in ml_scores if s is not None]
    if not valid:
        return 0.0
    return round(sum(valid) / len(valid) / 100.0, 6)


def _calculate_ioc_density(unique_ioc_count: int, event_count: int) -> float:
    """
    Compute the IOC density as the ratio of unique IOCs to total events.

    Capped at 1.0 (there can never be more unique IOCs than events in a
    well-formed cluster, but the cap guards against data inconsistencies).

    Args:
        unique_ioc_count: Number of distinct IOC IP addresses in the cluster.
        event_count:      Total number of events in the cluster.

    Returns:
        Float in [0.0, 1.0].  Returns 0.0 when event_count <= 0.

    Examples
    --------
    >>> _calculate_ioc_density(0, 10)
    0.0
    >>> _calculate_ioc_density(5, 10)
    0.5
    >>> _calculate_ioc_density(10, 10)
    1.0
    >>> _calculate_ioc_density(15, 10)   # capped
    1.0
    """
    if event_count <= 0:
        return 0.0
    if unique_ioc_count <= 0:
        return 0.0
    return min(1.0, unique_ioc_count / event_count)


def _multi_proto_bonus(protocols: Sequence[str]) -> float:
    """
    Return 1.0 if the campaign spans multiple distinct protocols, 0.0 otherwise.

    Args:
        protocols: List of protocol strings from the campaign cluster
                   (e.g. ``["TCP", "UDP"]``).

    Returns:
        ``1.0`` if ``len(unique protocols) > 1`` else ``0.0``.

    Examples
    --------
    >>> _multi_proto_bonus([])
    0.0
    >>> _multi_proto_bonus(["TCP"])
    0.0
    >>> _multi_proto_bonus(["TCP", "UDP"])
    1.0
    >>> _multi_proto_bonus(["TCP", "TCP", "UDP"])
    1.0
    """
    if not protocols:
        return 0.0
    unique = {str(p).strip().upper() for p in protocols if p}
    return 1.0 if len(unique) > 1 else 0.0


# ---------------------------------------------------------------------------
# Primary public function
# ---------------------------------------------------------------------------

def calculate_confidence(
    event_count: int,
    ml_scores: Sequence[float],
    unique_ioc_count: int,
    protocols: Sequence[str],
    cluster_size_cap: int = 200,
    weights: Optional[Dict[str, float]] = None,
) -> ConfidenceResult:
    """
    Calculate a composite confidence score for a campaign cluster.

    Combines four signals into a single weighted average:

      confidence = (
          w_cluster  * cluster_size_score
        + w_ml       * ml_avg_score
        + w_ioc      * ioc_density
        + w_multi    * multi_proto_bonus
      )

    Args:
        event_count:       Total number of events in the cluster.
        ml_scores:         List of ML threat/anomaly scores (0–100 scale)
                           from PacketLog rows associated with this cluster.
        unique_ioc_count:  Number of distinct IOC IP addresses observed.
        protocols:         List of network protocol strings from the cluster.
        cluster_size_cap:  Event count that maps to a cluster_size_score of 1.0.
                           Defaults to 200.
        weights:           Optional dict overriding DEFAULT_WEIGHTS.
                           Must contain keys: cluster_size, ml_avg,
                           ioc_density, multi_proto.

    Returns:
        A :class:`ConfidenceResult` NamedTuple with:
            - confidence          (float, clamped to [0.0, 1.0])
            - severity            (str: CRITICAL | HIGH | MEDIUM | LOW)
            - cluster_size_score  (float)
            - ml_avg_score        (float)
            - ioc_density         (float)
            - multi_proto_bonus   (float)
            - breakdown           (dict with all components and weights)

    Raises:
        ValueError: If a supplied weight dict has keys that don't sum to ~1.0
                    (tolerance ±0.02) to guard against misconfiguration.

    Examples
    --------
    >>> result = calculate_confidence(
    ...     event_count=150,
    ...     ml_scores=[80.0, 90.0, 70.0],
    ...     unique_ioc_count=10,
    ...     protocols=["TCP", "UDP"],
    ...     cluster_size_cap=200,
    ... )
    >>> 0.0 <= result.confidence <= 1.0
    True
    >>> result.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    True
    """
    # ── Resolve weights ───────────────────────────────────────────────────
    w = dict(DEFAULT_WEIGHTS)
    if weights is not None:
        w.update(weights)
        total = sum(w.values())
        if abs(total - 1.0) > 0.02:
            raise ValueError(
                f"Confidence weights must sum to ~1.0 (got {total:.4f}). "
                f"Weights: {w}"
            )

    w_cluster = w.get("cluster_size", DEFAULT_WEIGHTS["cluster_size"])
    w_ml      = w.get("ml_avg",       DEFAULT_WEIGHTS["ml_avg"])
    w_ioc     = w.get("ioc_density",  DEFAULT_WEIGHTS["ioc_density"])
    w_multi   = w.get("multi_proto",  DEFAULT_WEIGHTS["multi_proto"])

    # ── Compute components ────────────────────────────────────────────────
    css  = _normalise_cluster_size(event_count, cap=cluster_size_cap)
    mlas = _normalise_ml_scores(ml_scores)
    iod  = _calculate_ioc_density(unique_ioc_count, event_count)
    mpb  = _multi_proto_bonus(protocols)

    # ── Weighted average ──────────────────────────────────────────────────
    raw_confidence = (
        w_cluster * css
        + w_ml    * mlas
        + w_ioc   * iod
        + w_multi * mpb
    )
    confidence = round(max(0.0, min(1.0, raw_confidence)), 4)
    severity   = confidence_to_severity(confidence)

    breakdown = {
        "confidence":          confidence,
        "severity":            severity,
        "components": {
            "cluster_size_score": round(css,  4),
            "ml_avg_score":       round(mlas, 4),
            "ioc_density":        round(iod,  4),
            "multi_proto_bonus":  round(mpb,  4),
        },
        "weights": {
            "cluster_size": w_cluster,
            "ml_avg":       w_ml,
            "ioc_density":  w_ioc,
            "multi_proto":  w_multi,
        },
        "inputs": {
            "event_count":      event_count,
            "ml_score_count":   len([s for s in ml_scores if s is not None]),
            "unique_ioc_count": unique_ioc_count,
            "protocols":        list(protocols),
            "cluster_size_cap": cluster_size_cap,
        },
    }

    logger.debug(
        "[confidence_scoring] confidence=%.4f severity=%s "
        "(css=%.3f mlas=%.3f iod=%.3f mpb=%.1f)",
        confidence, severity, css, mlas, iod, mpb,
    )

    return ConfidenceResult(
        confidence=confidence,
        severity=severity,
        cluster_size_score=round(css,  4),
        ml_avg_score=round(mlas, 4),
        ioc_density=round(iod,  4),
        multi_proto_bonus=round(mpb,  4),
        breakdown=breakdown,
    )
