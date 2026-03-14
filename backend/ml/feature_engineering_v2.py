import re
import math
import statistics
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import Dict, List, Set, Any
import numpy as np


class FeatureExtractorV2:
    """
    Enhanced Feature Extractor with 12+ Behavioral Features.
    Extends base detection capabilities with temporal and payload patterns.
    """

    BEHAVIORAL_FEATURES = [
        "command_count",
        "avg_command_length",
        "shell_escape_count",
        "directory_traversal_count",
        "failed_login_count",
        "payload_entropy",
        "interaction_interval_var",
        "persistence_score",
        "ua_diversity",
        "lateral_movement_index",
        "sensitive_file_count",
        "payload_to_cmd_ratio",
    ]

    SENSITIVE_FILES = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "id_rsa",
        ".ssh/",
        "config.php",
        "settings.py",
        ".env",
        "web.config",
        "boot.ini",
    }

    SHELL_ESCAPES = {";", "&&", "||", "|", "`", "$(", "\\\n"}

    def __init__(self, window_seconds: int = 3600):
        self.window_seconds = window_seconds

        # State tracking (per source IP)
        self.ip_events = defaultdict(list)
        self.ip_user_agents = defaultdict(set)
        self.ip_destinations = defaultdict(set)
        self.ip_hourly_blocks = defaultdict(set)
        self.ip_login_failures = defaultdict(int)

    def extract_v2_features(self, event: dict) -> Dict[str, float]:
        src_ip = event.get("src_ip", "0.0.0.0")
        raw_data = str(event.get("raw_data", ""))
        timestamp = self._parse_timestamp(event.get("timestamp"))

        # Update trackers
        self.ip_events[src_ip].append(
            {"ts": timestamp, "data": raw_data, "dst": event.get("dst_ip")}
        )
        self.ip_user_agents[src_ip].add(event.get("user_agent", "None"))
        self.ip_destinations[src_ip].add(event.get("dst_ip"))
        self.ip_hourly_blocks[src_ip].add(timestamp.strftime("%Y-%m-%d-%H"))

        if "login_failed" in str(event.get("event", "")).lower():
            self.ip_login_failures[src_ip] += 1

        # Calculate features
        features = {}

        # 1. Command Count & Length
        commands = self._extract_commands(raw_data)
        features["command_count"] = float(len(commands))
        features["avg_command_length"] = (
            statistics.mean([len(c) for c in commands]) if commands else 0.0
        )

        # 2. Shell Escapes
        features["shell_escape_count"] = float(
            sum(1 for char in raw_data if char in self.SHELL_ESCAPES)
        )

        # 3. Directory Traversal
        features["directory_traversal_count"] = float(
            raw_data.count("../") + raw_data.count("..\\")
        )

        # 4. Failed Logins
        features["failed_login_count"] = float(self.ip_login_failures[src_ip])

        # 5. Payload Entropy
        features["payload_entropy"] = self._calculate_entropy(raw_data)

        # 6. Interaction Interval Variance
        features["interaction_interval_var"] = self._calculate_interval_variance(src_ip)

        # 7. Persistence Score
        features["persistence_score"] = float(len(self.ip_hourly_blocks[src_ip]))

        # 8. UA Diversity
        features["ua_diversity"] = float(len(self.ip_user_agents[src_ip]))

        # 9. Lateral Movement Index
        features["lateral_movement_index"] = len(self.ip_destinations[src_ip]) / len(
            self.ip_events[src_ip]
        )

        # 10. Sensitive File Access
        features["sensitive_file_count"] = float(
            sum(1 for f in self.SENSITIVE_FILES if f in raw_data)
        )

        # 11. Payload to Command Ratio
        features["payload_to_cmd_ratio"] = len(raw_data) / (len(commands) + 1)

        return features

    def _extract_commands(self, data: str) -> List[str]:
        # Simple heuristic: split by common delimiters
        return [c.strip() for c in re.split(r"[;&|]", data) if c.strip()]

    def _calculate_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        probs = [
            f / len(data)
            for f in defaultdict(int, {c: data.count(c) for c in set(data)}).values()
        ]
        return -sum(p * math.log2(p) for p in probs)

    def _calculate_interval_variance(self, src_ip: str) -> float:
        events = self.ip_events[src_ip]
        if len(events) < 3:
            return 0.0
        intervals = [
            (events[i + 1]["ts"] - events[i]["ts"]).total_seconds()
            for i in range(len(events) - 1)
        ]
        return float(statistics.variance(intervals))

    def _parse_timestamp(self, ts) -> datetime:
        if isinstance(ts, datetime):
            return ts.replace(tzinfo=timezone.utc) if not ts.tzinfo else ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except:
                pass
        return datetime.now(timezone.utc)


if __name__ == "__main__":
    # Test script
    extractor = FeatureExtractorV2()
    test_event = {
        "src_ip": "1.2.3.4",
        "dst_ip": "10.0.0.1",
        "raw_data": "/bin/sh -c 'cat /etc/passwd; echo hello'",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "command_execution",
        "user_agent": "Mozilla/5.0",
    }
    print("Testing Feature Extraction V2...")
    print(extractor.extract_v2_features(test_event))
