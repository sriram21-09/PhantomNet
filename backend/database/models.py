from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String)
    honeypot_type = Column(String)
    port = Column(Integer)
    raw_data = Column(Text)

class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    # 👇 THIS LINE WAS MISSING
    session_token = Column(String, unique=True, index=True) 
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    ip_address = Column(String)
    event_count = Column(Integer, default=1)