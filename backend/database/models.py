from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
try:
    from app_models import Base
except ImportError:
    from backend.app_models import Base

class AttackSession(Base):
    __tablename__ = "attack_sessions"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True)
    attacker_ip = Column(String, index=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    threat_score = Column(Float, default=0.0)
    
    # Relationship to events if needed, though not explicitly populated in seed script
    # events = relationship("Event", back_populates="session")

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

    # session = relationship("AttackSession", back_populates="events")
