import math
import threading
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import Dict, List, Any, Union
import numpy as np
import pandas as pd

try:
    from backend.ml.config.feature_schema import (
        CANONICAL_FEATURE_NAMES,
        CANONICAL_FEATURE_COUNT,
        CANONICAL_TARGET_NAME,
        SCHEMA_VERSION,
        validate_feature_vector,
        validate_feature_dict,
        dict_to_canonical_vector,
    )
except ImportError:
    from ml.config.feature_schema import (
        CANONICAL_FEATURE_NAMES,
        CANONICAL_FEATURE_COUNT,
        CANONICAL_TARGET_NAME,
        SCHEMA_VERSION,
        validate_feature_vector,
        validate_feature_dict,
        dict_to_canonical_vector,
    )


class FeatureExtractor:
    """
    PhantomNet Clean 12-Dimensional Feature Extractor (v3.0)
    -------------------------------------------------------
    Extracts pure network socket, transport, and behavioral flow observables.
    Strictly free from target leakage (threat_score) and label leakage (is_malicious).

    Authoritative schema defined in `backend.ml.config.feature_schema`.
    Thread-safe implementation with bounded sliding windows.
    """

    SCHEMA_VERSION = SCHEMA_VERSION
    FEATURE_NAMES = list(CANONICAL_FEATURE_NAMES)
    FEATURE_COUNT = CANONICAL_FEATURE_COUNT
    TARGET_NAME = CANONICAL_TARGET_NAME

    # Expose validation boundaries on class
    validate_feature_vector = staticmethod(validate_feature_vector)
    validate_feature_dict = staticmethod(validate_feature_dict)

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._lock = threading.RLock()

        # Stateful sliding-window trackers (per source IP)
        self.ip_timestamps = defaultdict(list)
        self.ip_packet_lengths = defaultdict(list)
        self.ip_dst_ips = defaultdict(list)
        self.ip_dst_ports = defaultdict(list)

    def reset_state(self):
        """Clears all in-memory rolling state."""
        with self._lock:
            self.ip_timestamps.clear()
            self.ip_packet_lengths.clear()
            self.ip_dst_ips.clear()
            self.ip_dst_ports.clear()

    # --------------------------------------------------
    # Public API
    # --------------------------------------------------

    def extract_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """
        Extracts the 12-dimensional feature dictionary from a raw event.
        Thread-safe and deterministic.
        """
        src_ip = str(event.get("src_ip") or "0.0.0.0")
        dst_ip = str(event.get("dst_ip") or "127.0.0.1")
        dst_port = self._safe_int(event.get("dst_port"), 0)
        src_port = self._safe_int(event.get("src_port"), 0)
        protocol = str(event.get("protocol") or "TCP").upper()
        length = self._safe_int(event.get("length"), 0)
        raw_data = str(event.get("raw_data") or event.get("payload") or "")
        now_ts = self._parse_timestamp(event.get("timestamp"))

        with self._lock:
            # Update history
            self.ip_timestamps[src_ip].append(now_ts)
            self.ip_packet_lengths[src_ip].append(length)
            self.ip_dst_ips[src_ip].append(dst_ip)
            self.ip_dst_ports[src_ip].append(dst_port)

            # Prune events older than window_seconds
            cutoff_60s = now_ts - timedelta(seconds=self.window_seconds)
            cutoff_10s = now_ts - timedelta(seconds=10)

            # Keep only items in window
            valid_indices = [
                i for i, ts in enumerate(self.ip_timestamps[src_ip])
                if ts >= cutoff_60s
            ]
            
            if not valid_indices:
                valid_indices = [len(self.ip_timestamps[src_ip]) - 1]

            ts_window = [self.ip_timestamps[src_ip][i] for i in valid_indices]
            len_window = [self.ip_packet_lengths[src_ip][i] for i in valid_indices]
            dst_ip_window = [self.ip_dst_ips[src_ip][i] for i in valid_indices]
            dst_port_window = [self.ip_dst_ports[src_ip][i] for i in valid_indices]

            # Update state with pruned lists
            self.ip_timestamps[src_ip] = ts_window
            self.ip_packet_lengths[src_ip] = len_window
            self.ip_dst_ips[src_ip] = dst_ip_window
            self.ip_dst_ports[src_ip] = dst_port_window

            # 1. packet_length
            feat_packet_length = float(length)

            # 2. protocol_encoding (TCP=1, UDP=2, ICMP=3, Other=0)
            if "TCP" in protocol:
                feat_protocol = 1.0
            elif "UDP" in protocol:
                feat_protocol = 2.0
            elif "ICMP" in protocol:
                feat_protocol = 3.0
            else:
                feat_protocol = 0.0

            # 3. dst_port_class (Well-known <=1023 -> 1, Registered 1024-49151 -> 2, Ephemeral -> 3)
            if dst_port <= 1023:
                feat_dst_port_class = 1.0
            elif dst_port <= 49151:
                feat_dst_port_class = 2.0
            else:
                feat_dst_port_class = 3.0

            # 4. src_port_ephemeral
            feat_src_port_ephemeral = 1.0 if src_port >= 1024 else 0.0

            # 5. event_rate_1m
            feat_event_rate_1m = float(len(ts_window))

            # 6. burst_rate_10s
            feat_burst_rate_10s = float(sum(1 for ts in ts_window if ts >= cutoff_10s))

            # 7. inter_arrival_mean & 8. inter_arrival_std
            if len(ts_window) >= 2:
                deltas = [
                    (ts_window[i] - ts_window[i - 1]).total_seconds()
                    for i in range(1, len(ts_window))
                ]
                # Filter out negative deltas caused by out-of-order logs
                deltas = [max(0.0, d) for d in deltas]
                feat_arr_mean = float(sum(deltas) / len(deltas))
                if len(deltas) >= 2:
                    var = sum((d - feat_arr_mean) ** 2 for d in deltas) / (len(deltas) - 1)
                    feat_arr_std = float(math.sqrt(var))
                else:
                    feat_arr_std = 0.0
            else:
                feat_arr_mean = 1.0
                feat_arr_std = 0.0

            # 9. packet_size_variance
            if len(len_window) >= 2:
                mean_l = sum(len_window) / len(len_window)
                var_l = sum((l - mean_l) ** 2 for l in len_window) / (len(len_window) - 1)
                feat_size_var = float(var_l)
            else:
                feat_size_var = 0.0

            # 10. payload_entropy
            feat_entropy = self._shannon_entropy(raw_data)

            # 11. unique_dst_ips
            feat_unique_dst_ips = float(len(set(dst_ip_window)))

            # 12. unique_dst_ports
            feat_unique_dst_ports = float(len(set(dst_port_window)))

        return {
            "packet_length": feat_packet_length,
            "protocol_encoding": feat_protocol,
            "dst_port_class": feat_dst_port_class,
            "src_port_ephemeral": feat_src_port_ephemeral,
            "event_rate_1m": feat_event_rate_1m,
            "burst_rate_10s": feat_burst_rate_10s,
            "inter_arrival_mean": feat_arr_mean,
            "inter_arrival_std": feat_arr_std,
            "packet_size_variance": feat_size_var,
            "payload_entropy": feat_entropy,
            "unique_dst_ips": feat_unique_dst_ips,
            "unique_dst_ports": feat_unique_dst_ports,
        }

    def extract_vector(self, event: Dict[str, Any]) -> List[float]:
        """
        Returns the validated, ordered 12-dimensional numerical vector.
        Strictly enforces CANONICAL_FEATURE_NAMES sequence.
        """
        feat_dict = self.extract_features(event)
        vec = dict_to_canonical_vector(feat_dict)
        validate_feature_vector(vec)
        return vec

    def to_vector(self, feature_dict: Dict[str, Any]) -> np.ndarray:
        """
        Converts a feature dict directly to a validated (1, 12) numpy array.
        """
        vec = dict_to_canonical_vector(feature_dict)
        return validate_feature_vector(vec)

    # --------------------------------------------------
    # Internal Helpers
    # --------------------------------------------------

    @staticmethod
    def _safe_int(val: Any, default: int = 0) -> int:
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        # Calculate byte-level Shannon entropy
        prob_dict = defaultdict(int)
        for char in data:
            prob_dict[char] += 1
        n = len(data)
        entropy = -sum((count / n) * math.log2(count / n) for count in prob_dict.values())
        return float(round(entropy, 4))

    @staticmethod
    def _parse_timestamp(ts: Any) -> datetime:
        if isinstance(ts, datetime):
            return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
        if isinstance(ts, str):
            try:
                # Handle ISO 8601 strings
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                pass
        return datetime.now(timezone.utc)
