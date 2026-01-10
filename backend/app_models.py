from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text
)
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class PacketLog(Base):
    """
    Unified event table for all protocols (SSH, HTTP, FTP, SMTP, etc.)
    This is the SINGLE source of truth for events, stats, and dashboard.
    """

    __tablename__ = "packet_logs"

    # Core identifiers
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Network metadata
    src_ip = Column(String(64), index=True, nullable=False)
    dst_ip = Column(String(64), nullable=True)
    protocol = Column(String(16), index=True, nullable=False)
    length = Column(Integer, default=0)

    # Detection & scoring
    is_malicious = Column(Boolean, default=False)
    threat_score = Column(Float, default=0.0)
    attack_type = Column(String(32), nullable=True)  # BENIGN / SUSPICIOUS / MALICIOUS

    # =========================
    # OPTIONAL SMTP FIELDS
    # =========================
    mail_from = Column(String(256), nullable=True)
    rcpt_to = Column(String(256), nullable=True)
    email_subject = Column(String(512), nullable=True)
    body_len = Column(Integer, nullable=True)

    def __repr__(self):
        return (
            f"<PacketLog id={self.id} "
            f"src_ip={self.src_ip} "
            f"protocol={self.protocol} "
            f"threat_score={self.threat_score}>"
        )


class TrafficStats(Base):
    """
    Cached / optional table.
    Not used as authoritative source.
    Safe to keep for future optimizations.
    """

    __tablename__ = "traffic_stats"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    total_events = Column(Integer, default=0)
    unique_ips = Column(Integer, default=0)
    active_honeypots = Column(Integer, default=0)
    avg_threat_score = Column(Float, default=0.0)
    critical_alerts = Column(Integer, default=0)
