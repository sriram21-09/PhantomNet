from datetime import datetime, timedelta, timezone
from collections import defaultdict
import statistics
from typing import Dict


class FeatureExtractor:
    """
    FeatureExtractor
    ----------------
    Implements EXACTLY the 15 ML features defined in:
    docs/FEATURE_EXTRACTION_SPEC_FINAL.md

    Source of truth:
    - packet_logs

    Notes:
    - READ-ONLY
    - No database writes
    - Deterministic behavior (best-effort)
    """

    FEATURE_NAMES = [
        "packet_length",
        "protocol_encoding",
        "source_ip_event_rate",
        "destination_port_class",
        "threat_score",
        "malicious_flag_ratio",
        "attack_type_frequency",
        "time_of_day_deviation",
        "burst_rate",
        "packet_size_variance",
        "honeypot_interaction_count",
        "session_duration_estimate",
        "unique_destination_count",
        "rolling_average_deviation",
        "z_score_anomaly",
    ]

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds

        # Stateful trackers (per source IP)
        self.ip_event_timestamps = defaultdict(list)
        self.ip_packet_lengths = defaultdict(list)
        self.ip_attack_types = defaultdict(list)
        self.ip_destinations = defaultdict(set)
        self.ip_honeypots = defaultdict(set)
        self.ip_malicious_flags = defaultdict(list)

    # --------------------------------------------------
    # Public API
    # --------------------------------------------------

    def extract_features(self, event: dict) -> Dict[str, float]:
        src_ip = event.get("src_ip", "0.0.0.0")
        timestamp = self._parse_timestamp(event.get("timestamp"))

        # Track state
        self.ip_event_timestamps[src_ip].append(timestamp)
        self.ip_packet_lengths[src_ip].append(int(event.get("length", 0)))
        self.ip_attack_types[src_ip].append(event.get("attack_type", "UNKNOWN"))
        self.ip_destinations[src_ip].add(event.get("dst_ip", "0.0.0.0"))
        self.ip_honeypots[src_ip].add(event.get("honeypot_type", "UNKNOWN"))
        self.ip_malicious_flags[src_ip].append(bool(event.get("is_malicious", False)))

        return {
            "packet_length": self.packet_length(event),
            "protocol_encoding": self.protocol_encoding(event),
            "source_ip_event_rate": self.source_ip_event_rate(src_ip, timestamp),
            "destination_port_class": self.destination_port_class(event),
            "threat_score": self.threat_score(event),
            "malicious_flag_ratio": self.malicious_flag_ratio(src_ip),
            "attack_type_frequency": self.attack_type_frequency(src_ip),
            "time_of_day_deviation": self.time_of_day_deviation(timestamp),
            "burst_rate": self.burst_rate(src_ip, timestamp),
            "packet_size_variance": self.packet_size_variance(src_ip),
            "honeypot_interaction_count": self.honeypot_interaction_count(src_ip),
            "session_duration_estimate": self.session_duration_estimate(src_ip),
            "unique_destination_count": self.unique_destination_count(src_ip),
            "rolling_average_deviation": self.rolling_average_deviation(src_ip),
            "z_score_anomaly": self.z_score_anomaly(src_ip),
        }

    # --------------------------------------------------
    # Feature Implementations
    # --------------------------------------------------

    def packet_length(self, event: dict) -> int:
        return int(event.get("length", 0))

    def protocol_encoding(self, event: dict) -> int:
        protocol_map = {"TCP": 1, "UDP": 2, "ICMP": 3}
        return protocol_map.get(event.get("protocol"), 0)

    def source_ip_event_rate(self, src_ip: str, now: datetime) -> float:
        window_start = now - timedelta(seconds=self.window_seconds)
        recent = [ts for ts in self.ip_event_timestamps[src_ip] if ts >= window_start]
        return len(recent) * (60 / self.window_seconds)

    def destination_port_class(self, event: dict) -> int:
        port = int(event.get("dst_port", 0))
        if port < 1024:
            return 1
        elif port < 49152:
            return 2
        return 3

    def threat_score(self, event: dict) -> float:
        return float(event.get("threat_score", 0.0))

    def malicious_flag_ratio(self, src_ip: str) -> float:
        flags = self.ip_malicious_flags[src_ip]
        return sum(flags) / len(flags) if flags else 0.0

    def attack_type_frequency(self, src_ip: str) -> int:
        attacks = self.ip_attack_types[src_ip]
        return max(attacks.count(a) for a in set(attacks)) if attacks else 0

    def time_of_day_deviation(self, timestamp: datetime) -> int:
        hour = timestamp.hour
        return int(hour < 6 or hour > 22)

    def burst_rate(self, src_ip: str, now: datetime) -> float:
        window_start = now - timedelta(seconds=10)
        recent = [ts for ts in self.ip_event_timestamps[src_ip] if ts >= window_start]
        return float(len(recent))

    def packet_size_variance(self, src_ip: str) -> float:
        sizes = self.ip_packet_lengths[src_ip]
        return float(statistics.variance(sizes)) if len(sizes) >= 2 else 0.0

    def honeypot_interaction_count(self, src_ip: str) -> int:
        return len(self.ip_honeypots[src_ip])

    def session_duration_estimate(self, src_ip: str) -> float:
        ts = self.ip_event_timestamps[src_ip]
        return (max(ts) - min(ts)).total_seconds() if len(ts) >= 2 else 0.0

    def unique_destination_count(self, src_ip: str) -> int:
        return len(self.ip_destinations[src_ip])

    def rolling_average_deviation(self, src_ip: str) -> float:
        sizes = self.ip_packet_lengths[src_ip]
        if not sizes:
            return 0.0
        avg = sum(sizes) / len(sizes)
        return float(sizes[-1] - avg)

    def z_score_anomaly(self, src_ip: str) -> float:
        sizes = self.ip_packet_lengths[src_ip]
        if len(sizes) < 2:
            return 0.0
        mean = statistics.mean(sizes)
        std = statistics.stdev(sizes)
        return float((sizes[-1] - mean) / std) if std != 0 else 0.0

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------

    def _parse_timestamp(self, ts) -> datetime:
        """
        Robust timestamp parser.
        Never crashes the pipeline.
        """
        if ts is None:
            return datetime.now(timezone.utc)

        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

        if isinstance(ts, str):
            ts = ts.strip()
            if not ts:
                return datetime.now(timezone.utc)
            try:
                ts = ts.replace("Z", "+00:00")
                return datetime.fromisoformat(ts)
            except Exception:
                return datetime.now(timezone.utc)

        return datetime.now(timezone.utc)


