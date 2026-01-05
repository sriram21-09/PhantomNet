from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class PacketLog(Base):
    __tablename__ = "packet_logs"

    id = Column(Integer, primary_key=True, index=True)
    # 👇 ADDED index=True for speed!
    timestamp = Column(DateTime, default=datetime.utcnow, index=True) 
    src_ip = Column(String, index=True) 
    dst_ip = Column(String)
    protocol = Column(String)
    length = Column(Integer)
    
    # AI Analysis Fields
    is_malicious = Column(Boolean, default=False)
    threat_score = Column(Float, default=0.0)
    attack_type = Column(String, nullable=True)

class TrafficStats(Base):
    __tablename__ = "traffic_stats"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    total_packets = Column(Integer, default=0)
    malicious_packets = Column(Integer, default=0)