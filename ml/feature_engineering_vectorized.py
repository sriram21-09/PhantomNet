import pandas as pd
import numpy as np

class VectorizedFeatureExtractor:
    """
    Pandas-based Vectorized Feature Extractor.
    Replaces loop-based dictionary extraction with fast DataFrame operations.
    """
    
    def extract_features_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
            
        features = pd.DataFrame(index=df.index)
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
            
        # 1. Packet length
        features['packet_length'] = df['length'].fillna(0).astype(int)
        
        # 2. Protocol encoding
        protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3}
        features['protocol_encoding'] = df['protocol'].map(protocol_map).fillna(0).astype(int)
        
        # 3. Destination port class
        features['destination_port_class'] = pd.cut(
            df['dst_port'].fillna(0).astype(int),
            bins=[-1, 1023, 49151, 65535],
            labels=[1, 2, 3]
        ).astype(int)
        
        # 4. Threat score
        features['threat_score'] = df['threat_score'].fillna(0.0).astype(float)
        
        # 5. Time of day deviation
        hours = df['timestamp'].dt.hour
        features['time_of_day_deviation'] = ((hours < 6) | (hours > 22)).astype(int)
        
        # Sort by IP and time for window operations
        df = df.sort_values(['src_ip', 'timestamp'])
        
        # 6. Malicious flag ratio (rolling or expanding per IP)
        # Assuming is_malicious is boolean/int
        if 'is_malicious' in df.columns:
            df['is_mal'] = df['is_malicious'].astype(int)
            features['malicious_flag_ratio'] = df.groupby('src_ip')['is_mal'].transform(lambda x: x.expanding().mean()).fillna(0.0)
        else:
            features['malicious_flag_ratio'] = 0.0

        # 7. Attack type frequency
        if 'attack_type' in df.columns:
            features['attack_type_frequency'] = df.groupby(['src_ip', 'attack_type'])['attack_type'].transform('count').fillna(0).astype(int)
        else:
            features['attack_type_frequency'] = 0
            
        # 8. Source IP Event Rate (events in last 60s)
        # A rough vectorized proxy: count events per IP per minute
        df['minute'] = df['timestamp'].dt.floor('Min')
        evt_rate = df.groupby(['src_ip', 'minute']).size().reset_index(name='rate')
        df_merged = df.merge(evt_rate, on=['src_ip', 'minute'], how='left')
        features['source_ip_event_rate'] = df_merged['rate'].fillna(0.0)
        
        # 9. Burst rate (events in last 10s)
        df['ten_sec'] = df['timestamp'].dt.floor('10s')
        burst = df.groupby(['src_ip', 'ten_sec']).size().reset_index(name='burst')
        df_merged2 = df.merge(burst, on=['src_ip', 'ten_sec'], how='left')
        features['burst_rate'] = df_merged2['burst'].fillna(0.0)
        
        # 10. Packet size variance
        features['packet_size_variance'] = df.groupby('src_ip')['length'].transform(lambda x: x.expanding().var()).fillna(0.0)
        
        # 11. Honeypot interaction count
        if 'honeypot_type' in df.columns:
            features['honeypot_interaction_count'] = df.groupby('src_ip')['honeypot_type'].transform(lambda x: (~x.duplicated()).cumsum()).fillna(0)
        else:
            features['honeypot_interaction_count'] = 0
            
        # 12. Session duration estimate
        features['session_duration_estimate'] = df.groupby('src_ip')['timestamp'].transform(lambda x: (x - x.min()).dt.total_seconds()).fillna(0.0)
        
        # 13. Unique destination count
        features['unique_destination_count'] = df.groupby('src_ip')['dst_ip'].transform(lambda x: (~x.duplicated()).cumsum()).fillna(0)
        
        # 14. Rolling average deviation
        roll_avg = df.groupby('src_ip')['length'].transform(lambda x: x.expanding().mean())
        features['rolling_average_deviation'] = (df['length'] - roll_avg).fillna(0.0)
        
        # 15. Z-score anomaly
        std = df.groupby('src_ip')['length'].transform(lambda x: x.expanding().std())
        features['z_score_anomaly'] = np.where(std > 0, (df['length'] - roll_avg) / std, 0.0)
        features['z_score_anomaly'] = features['z_score_anomaly'].fillna(0.0)
        
        # Realign to original index
        features = features.loc[df.index]
        return features
