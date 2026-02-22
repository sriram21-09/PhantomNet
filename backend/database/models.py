from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

# Define Base here to avoid circular imports
Base = declarative_base()

class PacketLog(Base):
    __tablename__ = "packet_logs"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String, index=True)
    dst_ip = Column(String)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0)
    protocol = Column(String)
    length = Column(Integer)
    attack_type = Column(String, nullable=True)
    threat_score = Column(Float, default=0.0)
    threat_level = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)
    is_malicious = Column(Boolean, default=False)
    event = Column(String, nullable=True) # e.g., "login_attempt"
    
    # GeoIP Enrichment
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

class TrafficStats(Base):
    __tablename__ = "traffic_stats"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    total_packets = Column(Integer, default=0)
    active_connections = Column(Integer, default=0)

class AttackSession(Base):
    __tablename__ = "attack_sessions"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True)
    attacker_ip = Column(String, index=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    threat_score = Column(Float, default=0.0)

class Event(Base):
    __tablename__ = "events"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("attack_sessions.id"), index=True)
    source_ip = Column(String)
    src_port = Column(Integer)
    honeypot_type = Column(String)
    raw_data = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

