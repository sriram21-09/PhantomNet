from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class EventCreate(BaseModel):
    timestamp: datetime
    source_ip: str
    honeypot_type: Optional[str] = None
    port: Optional[int] = None
    raw_data: Optional[str] = None
    class Config:
        from_attributes = True

class EventResponse(EventCreate):
    id: int