from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


# =========================
# Packet-level raw traffic
# =========================
class PacketLog(Base):
    __tablename__ = "packet_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    src_ip = Column(String, index=True)
    dst_ip = Column(String)
    protocol = Column(String)
    length = Column(Integer)

    # AI Analysis Fields
    is_malicious = Column(Boolean, default=False)
    threat_score = Column(Float, default=0.0)
    attack_type = Column(String, nullable=True)


# =========================
# High-level security events
# =========================
class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    source_ip = Column(String, index=True)
    honeypot_type = Column(String)
    port = Column(Integer, nullable=True)
    raw_data = Column(Text, nullable=True)

    # Normalized threat score (0–100)
    threat_score = Column(Integer, default=0)


# =========================
# Optional traffic statistics cache
# (NOT used by /api/stats anymore)
# =========================
class TrafficStats(Base):
    __tablename__ = "traffic_stats"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    total_packets = Column(Integer, default=0)
    malicious_packets = Column(Integer, default=0)
