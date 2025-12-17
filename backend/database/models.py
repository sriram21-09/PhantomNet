from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String, index=True)
    
    # 🆕 NEW COLUMNS (Issue #12)
    src_port = Column(Integer, nullable=True) 
    honeypot_type = Column(String)
    raw_data = Column(Text)
    
    # Link to Session
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True)
    session = relationship("Session", back_populates="events")

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    attacker_ip = Column(String, unique=True, index=True)
    
    # 🧠 NEW ML FIELDS (Issue #12)
    threat_score = Column(Float, default=0.0)
    status = Column(String, default="active")
    
    events = relationship("Event", back_populates="session")