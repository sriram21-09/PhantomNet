from pydantic import BaseModel
from datetime import datetime
from typing import Optional

# 1. Base Schema (What we receive from honeypots)
class EventCreate(BaseModel):
    timestamp: datetime
    source_ip: str
    honeypot_type: Optional[str] = None
    port: Optional[int] = None
    raw_data: Optional[str] = None

    class Config:
        from_attributes = True

# 2. Response Schema (What we show to the user, includes ID)
class EventResponse(EventCreate):
    id: int