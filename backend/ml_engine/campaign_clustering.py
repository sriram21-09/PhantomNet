"""
Campaign clustering service using DBSCAN.
Groups related network events into attack campaigns.
"""
import logging
from typing import List, Dict, Any, Optional

import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from database.database import SessionLocal
from database.models import PacketLog
from ml.feature_extractor import FeatureExtractor

logger = logging.getLogger("campaign_clustering")


class CampaignClusterer:
    """
    Handles DBSCAN-based clustering of network events to identify coordinated attack campaigns.
    """
    def __init__(self) -> None:
        """
        Initializes the CampaignClusterer with DBSCAN model and feature extractor.
        """
        # DBSCAN parameters tuned for temporal-IP clustering
        # eps is max distance between two samples for one to be considered as in the neighborhood of the other.
        # min_samples is the number of samples in a neighborhood for a point to be considered as a core point.
        self.model = DBSCAN(eps=0.5, min_samples=5, n_jobs=-1)
        self.feature_extractor = FeatureExtractor()

    def identify_campaigns(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Runs DBSCAN clustering across recent elevated threat logs to identify
        coordinated multi-stage attacker campaigns.
        """
        logger.info("Extracting attack groups from last %d hours.", hours_back)
        db: Session = SessionLocal()
        try:
            cutoff = datetime.now() - timedelta(hours=hours_back)

            # Target elevated threat classifications representing malicious actions
            logs = (
                db.query(PacketLog)
                .filter(
                    PacketLog.timestamp >= cutoff,
                    PacketLog.threat_level.in_(["MEDIUM", "HIGH", "CRITICAL"]),
                )
                .all()
            )

            if len(logs) < self.model.min_samples:
                logger.info("Not enough threats detected recently to form a campaign.")
                return {"campaign_count": 0, "campaigns": []}

            # Prepare Features for clustering
            # We convert raw properties into numeric values for spatial mapping
            features_list = []
            ip_map = []  # To map rows back to their original IPs

            for log in logs:
                event = {
                    "src_ip": log.src_ip,
                    "dst_ip": log.dst_ip or "127.0.0.1",
                    "dst_port": log.dst_port or 0,
                    "protocol": log.protocol or "UNKNOWN",
                    "length": log.length or 0,
                }
                extracted = self.feature_extractor.extract_features(event)
                features_list.append(extracted)
                ip_map.append(log)

            df = pd.DataFrame(features_list, columns=FeatureExtractor.FEATURE_NAMES)

            # Important: Keep `src_ip` behavior tightly grouped by enforcing its significance,
            # or apply specific scaling if needed. Assuming FeatureExtractor standardizes.
            predictions = self.model.fit_predict(df.values)

            # Analyze Clusters
            campaigns = {}
            for idx, cluster_id in enumerate(predictions):
                # -1 represents noise / outliers in DBSCAN
                if cluster_id == -1:
                    continue

                log_ref = ip_map[idx]
                c_id = f"campaign_{cluster_id}"

                if c_id not in campaigns:
                    campaigns[c_id] = {
                        "cluster_id": cluster_id,
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

            # Format Response
            response_campaigns = []
            for c_id, data in campaigns.items():
                response_campaigns.append(
                    {
                        "campaign_id": c_id,
                        "cluster_id": data["cluster_id"],
                        "unique_sources": list(data["source_ips"]),
                        "target_ports": list(data["target_ports"]),
                        "protocols": list(data["protocols"]),
                        "event_count": data["event_count"],
                        "start_time": data["start_time"].isoformat(),
                        "end_time": data["end_time"].isoformat(),
                        "duration_seconds": (
                            data["end_time"] - data["start_time"]
                        ).total_seconds(),
                    }
                )

            logger.info(f"Identified {len(response_campaigns)} active campaigns.")

            return {
                "campaign_count": len(response_campaigns),
                "timestamp_analyzed": datetime.now().isoformat(),
                "campaigns": response_campaigns,
            }

        except (ValueError, KeyError, AttributeError, RuntimeError) as e:
            logger.error("Error during campaign clustering: %s", e)
            return {"error": str(e), "campaign_count": 0, "campaigns": []}
        finally:
            db.close()


# Singleton
campaign_clusterer = CampaignClusterer()
