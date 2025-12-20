import pandas as pd
import numpy as np
from datetime import datetime

class FeatureExtractor:
    def __init__(self):
        # Configuration for normalization (Min/Max values)
        self.stats = {
            'duration': {'min': 0, 'max': 3600},
            'src_bytes': {'min': 0, 'max': 10000},
            'dst_bytes': {'min': 0, 'max': 10000}
        }
    
    def extract_time_features(self, start_time: str, end_time: str) -> float:
        """Calculates flow duration in seconds."""
        fmt = "%Y-%m-%d %H:%M:%S"
        try:
            t1 = datetime.strptime(start_time, fmt)
            t2 = datetime.strptime(end_time, fmt)
            duration = (t2 - t1).total_seconds()
            return max(0.0, duration)
        except:
            return 0.0

    def encode_protocol(self, protocol: str) -> list:
        """One-Hot Encodes Protocol: [is_TCP, is_UDP, is_ICMP]"""
        p = protocol.upper()
        return [
            1 if p == 'TCP' else 0,
            1 if p == 'UDP' else 0,
            1 if p == 'ICMP' else 0
        ]

    def extract_ip_patterns(self, src_ip: str, dst_ip: str) -> list:
        """Returns [is_internal_traffic, is_same_network]"""
        def is_private(ip):
            return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")
        
        src_priv = is_private(src_ip)
        dst_priv = is_private(dst_ip)
        
        return [
            1 if (src_priv and dst_priv) else 0, # Internal traffic
            1 if src_ip.split('.')[0:3] == dst_ip.split('.')[0:3] else 0 # Same Subnet
        ]

    def normalize(self, value, feature_name):
        """Scales value between 0 and 1."""
        min_v = self.stats.get(feature_name, {}).get('min', 0)
        max_v = self.stats.get(feature_name, {}).get('max', 1)
        if max_v - min_v == 0: return 0.0
        return round((value - min_v) / (max_v - min_v), 4)

    def generate_labeled_sample(self):
        """Generates dummy labeled data for testing."""
        return [
            {"start": "2025-12-20 10:00:00", "end": "2025-12-20 10:00:05", "proto": "TCP", "src": "192.168.1.5", "dst": "192.168.1.90", "label": "BENIGN"},
            {"start": "2025-12-20 10:05:00", "end": "2025-12-20 10:05:01", "proto": "UDP", "src": "10.0.0.5", "dst": "8.8.8.8", "label": "BENIGN"},
            {"start": "2025-12-20 10:10:00", "end": "2025-12-20 10:10:00", "proto": "TCP", "src": "192.168.1.100", "dst": "192.168.1.200", "label": "MALICIOUS"} # Port Scan
        ]