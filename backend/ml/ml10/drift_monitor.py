"""
PhantomNet Phase ML-10: Distribution Drift Monitoring Engine
============================================================
Quantifies feature-wise and composite distribution shift between baseline reference telemetry
and incoming streaming/batch traffic using PSI, Wasserstein distance, and Kolmogorov-Smirnov statistics.
"""

from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import scipy.stats as stats

from backend.ml.config.feature_schema import CANONICAL_FEATURE_NAMES


class DriftSeverity(str, Enum):
    NORMAL = "NORMAL"
    MILD = "MILD"
    MODERATE = "MODERATE"
    SEVERE = "SEVERE"


class DriftStatus:
    def __init__(
        self,
        severity: DriftSeverity,
        composite_psi: float,
        feature_psi: Dict[str, float],
        feature_wasserstein: Dict[str, float],
        feature_ks_stat: Dict[str, float],
        feature_ks_pval: Dict[str, float],
        flagged_features: List[str],
        sample_size: int,
        requires_adaptation: bool = False
    ):
        self.severity = severity
        self.composite_psi = composite_psi
        self.feature_psi = feature_psi
        self.feature_wasserstein = feature_wasserstein
        self.feature_ks_stat = feature_ks_stat
        self.feature_ks_pval = feature_ks_pval
        self.flagged_features = flagged_features
        self.sample_size = sample_size
        self.requires_adaptation = requires_adaptation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "composite_psi": float(self.composite_psi),
            "feature_psi": {k: float(v) for k, v in self.feature_psi.items()},
            "feature_wasserstein": {k: float(v) for k, v in self.feature_wasserstein.items()},
            "feature_ks_stat": {k: float(v) for k, v in self.feature_ks_stat.items()},
            "feature_ks_pval": {k: float(v) for k, v in self.feature_ks_pval.items()},
            "flagged_features": self.flagged_features,
            "sample_size": self.sample_size,
            "requires_adaptation": self.requires_adaptation
        }


def compute_psi_1d(expected: np.ndarray, actual: np.ndarray, num_bins: int = 10, epsilon: float = 1e-4) -> float:
    """
    Calculates 1D Population Stability Index (PSI) using quantile binning on expected reference data.
    """
    if len(expected) == 0 or len(actual) == 0:
        return 0.0

    # Handle constant vectors
    if np.all(expected == expected[0]) and np.all(actual == actual[0]):
        return 0.0 if expected[0] == actual[0] else 2.0

    quantiles = np.linspace(0, 100, num_bins + 1)
    bin_edges = np.percentile(expected, quantiles)
    bin_edges = np.unique(bin_edges)

    if len(bin_edges) < 2:
        bin_edges = np.array([np.min(expected) - 1e-3, np.max(expected) + 1e-3])

    exp_counts, _ = np.histogram(expected, bins=bin_edges)
    act_counts, _ = np.histogram(actual, bins=bin_edges)

    exp_pct = np.maximum(exp_counts / len(expected), epsilon)
    act_pct = np.maximum(act_counts / len(actual), epsilon)

    # Re-normalize
    exp_pct /= exp_pct.sum()
    act_pct /= act_pct.sum()

    psi_val = np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct))
    return float(max(0.0, psi_val))


class DistributionDriftMonitor:
    """
    Streaming and batch distribution drift monitor against a fixed baseline reference distribution.
    """

    def __init__(
        self,
        reference_data: np.ndarray,
        feature_names: Optional[List[str]] = None,
        psi_mild_threshold: float = 0.10,
        psi_moderate_threshold: float = 0.25,
        psi_severe_threshold: float = 0.50,
        window_size: int = 200
    ):
        self.feature_names = feature_names or list(CANONICAL_FEATURE_NAMES)
        self.reference_data = np.asarray(reference_data, dtype=np.float64)
        self.psi_mild = psi_mild_threshold
        self.psi_moderate = psi_moderate_threshold
        self.psi_severe = psi_severe_threshold
        self.window_size = window_size
        self.eval_stride = 50
        self.rolling_buffer: List[np.ndarray] = []
        self.cached_status: Optional[DriftStatus] = None

    def evaluate_batch(self, batch_data: np.ndarray) -> DriftStatus:
        """
        Evaluates distribution shift for an entire matrix of incoming data against reference.
        """
        batch = np.asarray(batch_data, dtype=np.float64)
        if batch.ndim == 1:
            batch = batch.reshape(1, -1)

        num_feats = len(self.feature_names)
        feat_psi = {}
        feat_wass = {}
        feat_ks_stat = {}
        feat_ks_pval = {}
        flagged_features = []

        for f_idx, f_name in enumerate(self.feature_names):
            exp_feat = self.reference_data[:, f_idx]
            act_feat = batch[:, f_idx]

            # 1. PSI
            psi_val = compute_psi_1d(exp_feat, act_feat)
            feat_psi[f_name] = psi_val

            # 2. Wasserstein Distance
            # Scale-normalize by reference IQR or std to make Wasserstein comparable across features
            ref_std = np.std(exp_feat)
            denom = ref_std if ref_std > 1e-6 else 1.0
            wass_val = stats.wasserstein_distance(exp_feat / denom, act_feat / denom)
            feat_wass[f_name] = float(wass_val)

            # 3. Two-sample Kolmogorov-Smirnov Test
            ks_res = stats.ks_2samp(exp_feat, act_feat)
            feat_ks_stat[f_name] = float(ks_res.statistic)
            feat_ks_pval[f_name] = float(ks_res.pvalue)

            if psi_val >= self.psi_moderate or (ks_res.pvalue < 0.001 and ks_res.statistic > 0.25):
                flagged_features.append(f_name)

        composite_psi = float(np.mean(list(feat_psi.values())))

        if composite_psi >= self.psi_severe or len(flagged_features) >= 6:
            severity = DriftSeverity.SEVERE
            requires_adaptation = True
        elif composite_psi >= self.psi_moderate or len(flagged_features) >= 3:
            severity = DriftSeverity.MODERATE
            requires_adaptation = True
        elif composite_psi >= self.psi_mild or len(flagged_features) >= 1:
            severity = DriftSeverity.MILD
            requires_adaptation = False
        else:
            severity = DriftSeverity.NORMAL
            requires_adaptation = False

        status = DriftStatus(
            severity=severity,
            composite_psi=composite_psi,
            feature_psi=feat_psi,
            feature_wasserstein=feat_wass,
            feature_ks_stat=feat_ks_stat,
            feature_ks_pval=feat_ks_pval,
            flagged_features=flagged_features,
            sample_size=len(batch),
            requires_adaptation=requires_adaptation
        )
        self.cached_status = status
        return status

    def process_sample(self, sample: np.ndarray) -> Optional[DriftStatus]:
        """
        Streaming interface: updates rolling buffer and evaluates drift every eval_stride samples.
        """
        self.rolling_buffer.append(np.asarray(sample, dtype=np.float64).flatten())
        if len(self.rolling_buffer) >= self.window_size:
            if self.cached_status is None or (len(self.rolling_buffer) % self.eval_stride == 0):
                window_matrix = np.array(self.rolling_buffer[-self.window_size:])
                return self.evaluate_batch(window_matrix)
            return self.cached_status
        return None
