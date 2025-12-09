from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime)
    source_ip = Column(String(64))
    honeypot_type = Column(String(64))
    port = Column(Integer)
    raw_data = Column(Text)

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(128))
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    src_ip = Column(String(64))
    honeypot_type = Column(String(64))
