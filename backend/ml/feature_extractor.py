import numpy as np
import pandas as pd
from datetime import datetime
import ipaddress
import math
from collections import defaultdict

class FeatureExtractor:
    def __init__(self):
        # Stateful trackers
        self.last_seen_timestamp = {}  # {ip: timestamp}
        self.failed_auth_tracker = defaultdict(int) # {ip: count}
        
        # Geo Mock Data (Simulating a lookup DB)
        self.geo_risk_scores = {
            "US": 1, "DE": 2, "CN": 8, "RU": 9, "BR": 5, "unknown": 3
        }

    def _calculate_entropy(self, text):
        """Calculates Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum(p * math.log(p) / math.log(2.0) for p in prob)
        return entropy

    def _get_geo_score(self, ip):
        """Mocks a GeoIP lookup based on IP octets."""
        try:
            # Deterministic mock: use last octet to pick a 'country'
            last_octet = int(ip.split('.')[-1])
            countries = list(self.geo_risk_scores.keys())
            country = countries[last_octet % len(countries)]
            return self.geo_risk_scores.get(country, 3)
        except:
            return 3 # Default risk

    def extract_features(self, log_entry):
        """
        Extracts a comprehensive feature vector from a raw log entry.
        Input: dict (raw log)
        Output: np.array (numerical feature vector)
        """
        features = []
        attacker_ip = log_entry.get("attacker_ip", "0.0.0.0")

        # --- 1. TEMPORAL FEATURES (3) ---
        timestamp = log_entry.get("timestamp")
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp)
        else:
            dt = timestamp if timestamp else datetime.now()
            
        features.append(dt.hour)
        features.append(dt.weekday())
        
        # Time Delta (Stateful)
        last_time = self.last_seen_timestamp.get(attacker_ip)
        if last_time:
            delta = (dt - last_time).total_seconds()
        else:
            delta = 0.0
        self.last_seen_timestamp[attacker_ip] = dt
        features.append(delta)

        # --- 2. NETWORK FEATURES (4) ---
        # IP Integer conversion
        try:
            ip_int = int(ipaddress.IPv4Address(attacker_ip))
        except:
            ip_int = 0
        features.append(float(ip_int))
        
        # Packet Count (New)
        features.append(float(log_entry.get("packet_count", 0)))
        
        # Source Geo Label (New - Mocked Risk Score)
        features.append(float(self._get_geo_score(attacker_ip)))
        
        # Is Private IP?
        is_private = 1.0 if ipaddress.IPv4Address(attacker_ip).is_private else 0.0
        features.append(is_private)

        # --- 3. CONTENT & BEHAVIORAL FEATURES (6) ---
        
        # Payload Size (New)
        payload = log_entry.get("payload", "")
        features.append(float(log_entry.get("payload_size", len(payload))))
        
        # Command Count (New - e.g., in a shell session)
        features.append(float(log_entry.get("command_count", 0)))
        
        # Failed Auth Count (Stateful - New)
        if log_entry.get("status") == "Failed":
            self.failed_auth_tracker[attacker_ip] += 1
        # We feature the CURRENT count for this IP
        features.append(float(self.failed_auth_tracker[attacker_ip]))
        
        # Unique Headers Count (New)
        headers = log_entry.get("headers", {})
        features.append(float(len(headers)))
        
        # URL Count (New - e.g., in HTTP request)
        features.append(float(log_entry.get("url_count", 0)))

        # Entropy of Payload (New)
        # If explicit payload field exists, use it; otherwise fallback to password/user combination
        target_text = payload if payload else (log_entry.get("username", "") + log_entry.get("password", ""))
        features.append(self._calculate_entropy(target_text))

        return np.array(features, dtype=np.float32)