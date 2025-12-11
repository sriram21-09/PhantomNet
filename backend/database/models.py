from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()

class Event(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime)
    source_ip = Column(String)
    honeypot_type = Column(String)
    port = Column(Integer)
    raw_data = Column(Text)

class Session(Base):
    __tablename__ = 'sessions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, default=lambda: str(uuid.uuid4()))
    src_ip = Column(String)
    honeypot_type = Column(String)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    event_count = Column(Integer)