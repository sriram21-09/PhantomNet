from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class EventCreate(BaseModel):
    source_ip: str
    honeypot_type: str
    port: int
    raw_data: str
    timestamp: Optional[datetime] = None   # 👈 OPTIONAL

class EventResponse(BaseModel):
    id: int
    source_ip: str
    honeypot_type: str
    port: int
    raw_data: str
    timestamp: datetime

    class Config:
        orm_mode = True