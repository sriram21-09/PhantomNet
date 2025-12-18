from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    source_ip = Column(String, nullable=False, index=True)
    honeypot_type = Column(String, nullable=False)
    port = Column(Integer, nullable=True)
    raw_data = Column(Text, nullable=True)