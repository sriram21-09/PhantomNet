from datetime import datetime, timedelta
from collections import defaultdict
import statistics


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
    - Deterministic behavior
    """

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

    def extract_features(self, event: dict) -> dict:
        """
        Extract the full 15-feature vector for a single packet_logs event.
        """

        src_ip = event.get("src_ip")
        timestamp = self._parse_timestamp(event.get("timestamp"))

        # Track state
        self.ip_event_timestamps[src_ip].append(timestamp)
        self.ip_packet_lengths[src_ip].append(event.get("length", 0))
        self.ip_attack_types[src_ip].append(event.get("attack_type"))
        self.ip_destinations[src_ip].add(event.get("dst_ip"))
        self.ip_honeypots[src_ip].add(event.get("honeypot_type"))
        self.ip_malicious_flags[src_ip].append(bool(event.get("is_malicious", False)))

        return {
            # 1
            "packet_length": self.packet_length(event),
            # 2
            "protocol_encoding": self.protocol_encoding(event),
            # 3
            "source_ip_event_rate": self.source_ip_event_rate(src_ip, timestamp),
            # 4
            "destination_port_class": self.destination_port_class(event),
            # 5
            "threat_score": self.threat_score(event),
            # 6
            "malicious_flag_ratio": self.malicious_flag_ratio(src_ip),
            # 7
            "attack_type_frequency": self.attack_type_frequency(src_ip),
            # 8
            "time_of_day_deviation": self.time_of_day_deviation(timestamp),
            # 9
            "burst_rate": self.burst_rate(src_ip, timestamp),
            # 10
            "packet_size_variance": self.packet_size_variance(src_ip),
            # 11
            "honeypot_interaction_count": self.honeypot_interaction_count(src_ip),
            # 12
            "session_duration_estimate": self.session_duration_estimate(src_ip),
            # 13
            "unique_destination_count": self.unique_destination_count(src_ip),
            # 14
            "rolling_average_deviation": self.rolling_average_deviation(src_ip),
            # 15
            "z_score_anomaly": self.z_score_anomaly(src_ip),
        }

    # --------------------------------------------------
    # Feature Implementations (15/15)
    # --------------------------------------------------

    # 1. Packet Length
    def packet_length(self, event: dict) -> int:
        return int(event.get("length", 0))

    # 2. Protocol Encoding
    def protocol_encoding(self, event: dict) -> int:
        protocol_map = {"TCP": 1, "UDP": 2, "ICMP": 3}
        return protocol_map.get(event.get("protocol"), 0)

    # 3. Source IP Event Rate (events per minute)
    def source_ip_event_rate(self, src_ip: str, now: datetime) -> float:
        window_start = now - timedelta(seconds=self.window_seconds)
        recent = [
            ts for ts in self.ip_event_timestamps[src_ip]
            if ts >= window_start
        ]
        return len(recent) * (60 / self.window_seconds)

    # 4. Destination Port Class
    def destination_port_class(self, event: dict) -> int:
        port = int(event.get("dst_port", 0))
        if port < 1024:
            return 1  # well-known
        elif port < 49152:
            return 2  # registered
        else:
            return 3  # ephemeral

    # 5. Threat Score
    def threat_score(self, event: dict) -> float:
        return float(event.get("threat_score", 0.0))

    # 6. Malicious Flag Ratio (FIXED)
    def malicious_flag_ratio(self, src_ip: str) -> float:
        flags = self.ip_malicious_flags[src_ip]
        if not flags:
            return 0.0
        malicious_count = sum(1 for f in flags if f)
        return malicious_count / len(flags)

    # 7. Attack Type Frequency
    def attack_type_frequency(self, src_ip: str) -> int:
        attacks = self.ip_attack_types[src_ip]
        if not attacks:
            return 0
        return max(attacks.count(a) for a in set(attacks))

    # 8. Time of Day Deviation
    def time_of_day_deviation(self, timestamp: datetime) -> bool:
        hour = timestamp.hour
        return hour < 6 or hour > 22

    # 9. Burst Rate (events in last 10 seconds)
    def burst_rate(self, src_ip: str, now: datetime) -> float:
        window_start = now - timedelta(seconds=10)
        recent = [
            ts for ts in self.ip_event_timestamps[src_ip]
            if ts >= window_start
        ]
        return float(len(recent))

    # 10. Packet Size Variance
    def packet_size_variance(self, src_ip: str) -> float:
        sizes = self.ip_packet_lengths[src_ip]
        if len(sizes) < 2:
            return 0.0
        return float(statistics.variance(sizes))

    # 11. Honeypot Interaction Count
    def honeypot_interaction_count(self, src_ip: str) -> int:
        return len(self.ip_honeypots[src_ip])

    # 12. Session Duration Estimate
    def session_duration_estimate(self, src_ip: str) -> float:
        timestamps = self.ip_event_timestamps[src_ip]
        if len(timestamps) < 2:
            return 0.0
        return (max(timestamps) - min(timestamps)).total_seconds()

    # 13. Unique Destination Count
    def unique_destination_count(self, src_ip: str) -> int:
        return len(self.ip_destinations[src_ip])

    # 14. Rolling Average Deviation
    def rolling_average_deviation(self, src_ip: str) -> float:
        sizes = self.ip_packet_lengths[src_ip]
        if not sizes:
            return 0.0
        avg = sum(sizes) / len(sizes)
        return float(sizes[-1] - avg)

    # 15. Z-Score Anomaly (packet-size based, Week 6 acceptable)
    def z_score_anomaly(self, src_ip: str) -> float:
        sizes = self.ip_packet_lengths[src_ip]
        if len(sizes) < 2:
            return 0.0
        mean = statistics.mean(sizes)
        std = statistics.stdev(sizes)
        if std == 0:
            return 0.0
        return float((sizes[-1] - mean) / std)

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------

    def _parse_timestamp(self, ts) -> datetime:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            return datetime.fromisoformat(ts)
        return datetime.utcnow()
