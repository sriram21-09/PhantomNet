from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

# Define Base here to avoid circular imports
Base = declarative_base()

class PacketLog(Base):
    __tablename__ = "packet_logs"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0)
    protocol = Column(String, index=True)
    length = Column(Integer)
    attack_type = Column(String, nullable=True)
    threat_score = Column(Float, default=0.0, index=True)
    threat_level = Column(String, nullable=True, index=True)
    confidence = Column(Float, nullable=True)
    is_malicious = Column(Boolean, default=False)
    event = Column(String, nullable=True) # e.g., "login_attempt"

class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    level = Column(String, index=True) # INFO, WARNING, CRITICAL
    type = Column(String, index=True) # CORRELATION, BASELINE, INTRUSION
    source_ip = Column(String, index=True, nullable=True)
    description = Column(String)
    details = Column(Text, nullable=True) # JSON or detailed string
    is_resolved = Column(Boolean, default=False)
    
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
    source_ip = Column(String, index=True)
    src_port = Column(Integer)
    honeypot_type = Column(String)
    raw_data = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # PCAP Capture
    pcap_path = Column(String, nullable=True)  # Path to associated PCAP file

    # GeoIP Enrichment
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

class HoneypotNode(Base):
    __tablename__ = "honeypot_nodes"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(String, unique=True, index=True)
    hostname = Column(String)
    ip_address = Column(String)
    status = Column(String, default="active") # active, inactive, pending
    last_seen = Column(DateTime, default=datetime.utcnow)
    honeypot_type = Column(String) # SSH, HTTP, etc.
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=True)

    policy = relationship("Policy", back_populates="nodes")

class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    description = Column(String)
    config = Column(String) # JSON string for now
    created_at = Column(DateTime, default=datetime.utcnow)

    nodes = relationship("HoneypotNode", back_populates="policy")

class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    template_type = Column(String) # Executive Summary, Technical Detail, etc.
    frequency = Column(String) # Daily, Weekly, Monthly
    schedule_time = Column(String) # "HH:MM" or more complex format
    recipients = Column(String) # Comma-separated emails
    filters = Column(Text) # JSON string of filters
    day_of_week = Column(String, nullable=True) # mon, tue, etc.
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class InvestigationCase(Base):
    __tablename__ = "investigation_cases"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(Text)
    status = Column(String, default="Open") # Open, In Progress, Closed
    priority = Column(String, default="Medium") # Low, Medium, High, Critical
    assigned_to = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)

    evidence = relationship("CaseEvidence", back_populates="case", cascade="all, delete-orphan")

class CaseEvidence(Base):
    __tablename__ = "case_evidence"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("investigation_cases.id"))
    event_id = Column(Integer, nullable=True) # ID from PacketLog or Event table
    event_type = Column(String) # "packet_log" or "honeypot_event"
    notes = Column(Text, nullable=True)
    added_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("InvestigationCase", back_populates="evidence")

class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, index=True) # IP, Domain, MD5, SHA256, URL
    value = Column(String, index=True)
    description = Column(String, nullable=True)
    threat_level = Column(String, default="Medium")
    is_watchlist = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class SearchHistory(Base):
    __tablename__ = "search_history"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    query_json = Column(Text) # JSON string of the query
    result_count = Column(Integer)
    executed_at = Column(DateTime, default=datetime.utcnow)
    analyst_name = Column(String, nullable=True)

class PcapCapture(Base):
    __tablename__ = "pcap_captures"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True, index=True)
    file_path = Column(String)
    file_size = Column(Integer, default=0)  # bytes
    packet_count = Column(Integer, default=0)
    protocol_summary = Column(Text, nullable=True)  # JSON string
    capture_duration = Column(Float, default=0.0)  # seconds
    analysis_status = Column(String, default="pending")  # pending, analyzing, complete, error
    threat_patterns = Column(Text, nullable=True)  # JSON string of detected patterns
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # 30-day retention
