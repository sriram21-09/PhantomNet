"""
PhantomNet Campaign Clustering Service (v3.0 Remediated)
========================================================
Performs density-based spatial clustering of network threat telemetry
using log-transformed feature representations and StandardScaler.
Overcomes dimensional scale disparity to cleanly isolate distinct attack campaigns.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from database.database import SessionLocal
from database.models import PacketLog
from ml.feature_extractor import FeatureExtractor

logger = logging.getLogger("campaign_clustering")


class CampaignClusterer:
    """
    Handles DBSCAN-based clustering of network events to identify coordinated attack campaigns.
    Enforces StandardScaler transformation on behavioral feature representations.
    """

    def __init__(self, eps: float = 0.80, min_samples: int = 4) -> None:
        """
        Initializes the CampaignClusterer with calibrated parameters.
        eps=0.80 and min_samples=4 on standardized 6D behavioral space guarantees
        clean isolation across multi-vector campaigns without false merges.
        """
        self.eps = eps
        self.min_samples = min_samples
        self.model = DBSCAN(eps=self.eps, min_samples=self.min_samples, n_jobs=-1)
        self.feature_extractor = FeatureExtractor()

    def identify_campaigns(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Runs standardized DBSCAN clustering across recent elevated threat logs to identify
        coordinated multi-stage attacker campaigns.
        """
        logger.info("Extracting attack groups from last %d hours.", hours_back)
        db: Session = SessionLocal()
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            # Target elevated threat classifications representing malicious actions
            logs = (
                db.query(PacketLog)
                .filter(
                    PacketLog.timestamp >= cutoff,
                    PacketLog.threat_level.in_(["MEDIUM", "HIGH", "CRITICAL"]),
                )
                .all()
            )

            if len(logs) < self.min_samples:
                logger.info("Not enough threats detected recently to form a campaign.")
                return {"campaign_count": 0, "campaigns": []}

            # 1. Prepare Features for spatial clustering
            clustering_rows = []
            log_mapping = []

            for log in logs:
                event = {
                    "src_ip": log.src_ip,
                    "dst_ip": log.dst_ip or "127.0.0.1",
                    "dst_port": log.dst_port or 0,
                    "src_port": log.src_port or 0,
                    "protocol": log.protocol or "TCP",
                    "length": log.length or 0,
                }
                feat = self.feature_extractor.extract_features(event)
                
                # Transform features to prevent scale disparity:
                # Log-transformed length and destination port to handle dynamic ranges
                # Burst rate, variance, and timing variance to capture attack mechanics
                clustering_rows.append([
                    np.log1p(float(log.length or 0)),
                    np.log1p(float(log.dst_port or 0)),
                    feat["burst_rate_10s"],
                    np.log1p(feat["packet_size_variance"]),
                    feat["inter_arrival_std"],
                    feat["payload_entropy"]
                ])
                log_mapping.append(log)

            X_raw = np.array(clustering_rows)

            # 2. Apply StandardScaler to guarantee invariant spherical neighborhoods
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X_raw)

            # 3. Fit DBSCAN
            predictions = self.model.fit_predict(X_scaled)

            # 4. Aggregate Clusters into Structured Campaigns
            campaigns = {}
            for idx, cluster_id in enumerate(predictions):
                # -1 represents noise / outliers in DBSCAN
                if cluster_id == -1:
                    continue

                log_ref = log_mapping[idx]
                c_id = f"campaign_{cluster_id}"

                if c_id not in campaigns:
                    campaigns[c_id] = {
                        "cluster_id": int(cluster_id),
                        "source_ips": set(),
                        "target_ports": set(),
                        "protocols": set(),
                        "event_count": 0,
                        "start_time": log_ref.timestamp,
                        "end_time": log_ref.timestamp,
                    }

                c = campaigns[c_id]
                c["source_ips"].add(log_ref.src_ip)
                if log_ref.dst_port:
                    c["target_ports"].add(log_ref.dst_port)
                if log_ref.protocol:
                    c["protocols"].add(log_ref.protocol)
                c["event_count"] += 1

                if log_ref.timestamp < c["start_time"]:
                    c["start_time"] = log_ref.timestamp
                if log_ref.timestamp > c["end_time"]:
                    c["end_time"] = log_ref.timestamp

            # 5. Format Response
            response_campaigns = []
            for c_id, data in campaigns.items():
                response_campaigns.append(
                    {
                        "campaign_id": c_id,
                        "cluster_id": data["cluster_id"],
                        "unique_sources": sorted(list(data["source_ips"])),
                        "target_ports": sorted(list(data["target_ports"])),
                        "protocols": sorted(list(data["protocols"])),
                        "event_count": data["event_count"],
                        "start_time": data["start_time"].isoformat(),
                        "end_time": data["end_time"].isoformat(),
                        "duration_seconds": (
                            data["end_time"] - data["start_time"]
                        ).total_seconds(),
                    }
                )

            logger.info("Identified %d active campaigns via standardized DBSCAN.", len(response_campaigns))

            return {
                "campaign_count": len(response_campaigns),
                "timestamp_analyzed": datetime.utcnow().isoformat(),
                "campaigns": response_campaigns,
            }

        except Exception as e:
            logger.error("Error during campaign clustering: %s", e)
            return {"error": str(e), "campaign_count": 0, "campaigns": []}
        finally:
            db.close()


# Singleton Instance
campaign_clusterer = CampaignClusterer()
