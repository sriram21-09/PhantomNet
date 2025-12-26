from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Index
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class PacketLog(Base):
    """
    Database Schema for Network Traffic Logs.
    
    Indexes:
    - timestamp: Optimizes time-range queries (e.g., "Show me attacks from last hour")
    - src_ip: Optimizes searching for specific attackers
    """
    __tablename__ = "packet_logs"

    # Primary Key
    id = Column(Integer, primary_key=True, index=True)

    # 1. Validation Constraints (nullable=False ensures data integrity)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # 2. Traffic Data
    src_ip = Column(String(15), nullable=False, index=True) # Index for fast IP lookup
    dst_ip = Column(String(15), nullable=False)
    protocol = Column(String(10), nullable=False)
    length = Column(Integer, nullable=False)
    
    # 3. AI Analysis Results
    is_malicious = Column(Boolean, default=False)
    threat_score = Column(Float, default=0.0) # 0.0 to 1.0
    attack_type = Column(String(50), nullable=True) # e.g. "DDoS", "Port Scan"

    # Documentation: Explicit Index definition (optional, but good for complex indexes)
    __table_args__ = (
        Index('idx_time_ip', 'timestamp', 'src_ip'), # Composite index example
    )

    def __repr__(self):
        return f"<PacketLog(time={self.timestamp}, src={self.src_ip}, score={self.threat_score})>"
    # Add 'import json' at the very top of the file if it's missing
import json 

class TrafficStats(Base):
    """
    Statistics Cache Table.
    Stores pre-calculated summaries to make the dashboard fast.
    """
    __tablename__ = "traffic_stats"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True) 
    
    # 1. High-Level Counts
    total_attacks = Column(Integer, default=0)
    unique_attackers = Column(Integer, default=0)
    
    # 2. Attacks by Protocol (Stored as a JSON string, e.g., '{"TCP": 50, "UDP": 12}')
    attacks_by_type = Column(String, default="{}") 
    
    last_updated = Column(DateTime, default=datetime.utcnow)