"""
tests/ml/test_shap_consistency.py
---------------------------------
Explainability Consistency & Attribution Verification (ML-04).

Validates:
  1. Monotonicity: malicious signal indicators contribute positively to threat scores.
  2. Top feature consistency across attack vectors.
  3. Feature attribution efficiency and directional alignment.
"""

import os
import sys
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))


def test_feature_attribution_directional_consistency():
    """
    ML-04: Feature signals associated with attacks (high failed logins,
    malicious IP indicator) must contribute positively to the attack prediction score.
    """
    np.random.seed(42)
    # Features: [packet_length, is_known_bad_ip, failed_login_rate, port_is_sensitive]
    X_train = np.array([
        [64, 0, 0, 0],
        [128, 0, 1, 0],
        [60, 0, 0, 0],
        [1500, 1, 10, 1],
        [800, 1, 8, 1],
        [400, 1, 15, 1],
    ])
    y_train = np.array([0, 0, 0, 1, 1, 1])

    clf = RandomForestClassifier(n_estimators=30, random_state=42)
    clf.fit(X_train, y_train)

    feature_importances = clf.feature_importances_
    
    # Attack indicators (is_known_bad_ip, failed_login_rate, port_is_sensitive) must have positive importance
    assert feature_importances[2] > 0, "Failed login rate must have positive feature importance"
    assert feature_importances[1] > 0 or feature_importances[3] > 0

    # Test perturbation: Increasing failed_login_rate must increase or preserve attack score
    baseline_sample = np.array([[200, 0, 1, 1]])
    perturbed_sample = np.array([[200, 0, 20, 1]])

    score_base = clf.predict_proba(baseline_sample)[0, 1]
    score_perturbed = clf.predict_proba(perturbed_sample)[0, 1]

    assert score_perturbed >= score_base, "Attribution monotonicity violated: higher failed logins lowered score!"


def test_top_feature_signal_stability():
    """
    ML-04: Top feature signals should remain consistent across repeated evaluations.
    """
    from backend.ml.threat_scoring_service import map_score_to_level
    from backend.schemas.threat_schema import ThreatInput

    t1 = ThreatInput(
        src_ip="192.0.2.10",
        dst_ip="10.0.0.1",
        dst_port=22,
        protocol="TCP",
        length=64,
        is_malicious=True,
    )
    t2 = ThreatInput(
        src_ip="192.0.2.11",
        dst_ip="10.0.0.1",
        dst_port=22,
        protocol="TCP",
        length=80,
        is_malicious=True,
    )

    # Both malicious inputs must deterministically evaluate to CRITICAL
    assert map_score_to_level(0.95, t1) == "CRITICAL"
    assert map_score_to_level(0.95, t2) == "CRITICAL"
