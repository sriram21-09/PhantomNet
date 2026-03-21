import math
from typing import Dict
from backend.ml.feature_extractor import FeatureExtractor
from backend.ml.feature_engineering_v2 import FeatureExtractorV2

class CompleteFeatureExtractor:
    """
    Consolidates FeatureExtractor (15 features) and FeatureExtractorV2 (12 features),
    and adds 5 new features to reach 32 features total.
    """
    def __init__(self, window_seconds: int = 60):
        self.base_extractor = FeatureExtractor(window_seconds=window_seconds)
        self.v2_extractor = FeatureExtractorV2(window_seconds=window_seconds)
        
        # Track state for new features (grouped by src_ip)
        from collections import defaultdict
        self.ip_dst_ports = defaultdict(set)
        self.ip_payload_sizes = defaultdict(list)
        self.ip_error_counts = defaultdict(int)
        self.ip_total_events = defaultdict(int)

    def extract_features(self, event: dict) -> Dict[str, float]:
        sanitized_event = event.copy()
        for field, cast_fn, default in [("length", int, 0), ("dst_port", int, 0), ("threat_score", float, 0.0)]:
            try:
                val = event.get(field)
                sanitized_event[field] = cast_fn(val) if val is not None else default
            except (ValueError, TypeError):
                sanitized_event[field] = default
                
        src_ip = sanitized_event.get("src_ip", "0.0.0.0")
        if src_ip is None:
            src_ip = "0.0.0.0"
            
        # Update trackers for new features
        self.ip_dst_ports[src_ip].add(sanitized_event["dst_port"])
            
        raw_data = str(sanitized_event.get("raw_data", ""))
        self.ip_payload_sizes[src_ip].append(len(raw_data))
        
        event_type = str(sanitized_event.get("event", "")).lower()
        status_code = sanitized_event.get("status_code", 200)
        try:
            is_error = "error" in event_type or int(status_code) >= 400
        except (ValueError, TypeError):
            is_error = "error" in event_type
            
        if is_error:
            self.ip_error_counts[src_ip] += 1
            
        self.ip_total_events[src_ip] += 1
        
        # 1. Get Base Features (15)
        base_features = self.base_extractor.extract_features(sanitized_event)
        
        # 2. Get V2 Features (12)
        v2_features = self.v2_extractor.extract_v2_features(sanitized_event)
        
        # 3. Calculate 5 New Features
        total_events = self.ip_total_events[src_ip]
        
        unique_port_count = float(len(self.ip_dst_ports[src_ip]))
        
        payloads = self.ip_payload_sizes[src_ip]
        average_payload_size = float(sum(payloads) / len(payloads)) if payloads else 0.0
        
        error_rate = float(self.ip_error_counts[src_ip] / total_events) if total_events > 0 else 0.0
        
        failed_logins = self.v2_extractor.ip_login_failures.get(src_ip, 0)
        auth_failure_ratio = float(failed_logins / total_events) if total_events > 0 else 0.0
        
        session_duration = base_features.get("session_duration_estimate", 0.0)
        request_velocity = float(total_events / session_duration) if session_duration > 0 else float(total_events)
        
        new_features = {
            "unique_port_count": unique_port_count,
            "average_payload_size": average_payload_size,
            "error_rate": error_rate,
            "auth_failure_ratio": auth_failure_ratio,
            "request_velocity": request_velocity
        }
        
        # Combine all features (15 + 12 + 5 = 32)
        all_features = {}
        all_features.update(base_features)
        all_features.update(v2_features)
        all_features.update(new_features)
        
        # Ensure all values are floats to prevent NaN / inf issues
        for k, v in all_features.items():
            try:
                val = float(v)
                if math.isnan(val) or math.isinf(val):
                    all_features[k] = 0.0
                else:
                    all_features[k] = val
            except (ValueError, TypeError):
                all_features[k] = 0.0
                
        return all_features
