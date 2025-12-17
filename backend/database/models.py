from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database.database import Base
from datetime import datetime

class AttackSession(Base):  # 👈 Renamed from 'Session' to 'AttackSession'
    __tablename__ = "attack_sessions"

    id = Column(Integer, primary_key=True, index=True)
    attacker_ip = Column(String, index=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    threat_score = Column(Float, default=0.0)
    status = Column(String, default="active")

    # Relationship
    events = relationship("Event", back_populates="session")

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("attack_sessions.id")) # 👈 Updated FK
    
    source_ip = Column(String, index=True)
    src_port = Column(Integer)
    honeypot_type = Column(String)
    raw_data = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationship
    session = relationship("AttackSession", back_populates="events") # 👈 Updated