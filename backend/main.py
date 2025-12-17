from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from database.models import Base, Event
from database.database import SessionLocal, engine

# Create Tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], 
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# 🆕 Updated Input Model
class LogInput(BaseModel):
    source_ip: str
    src_port: int = 0      # Default to 0 if missing
    protocol: str 
    details: str   

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    return db.query(Event).order_by(Event.timestamp.desc()).limit(50).all()

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Event.id)).scalar()
    unique = db.query(func.count(distinct(Event.source_ip))).scalar()
    return {"total_events": total, "unique_ips": unique}

@app.post("/api/logs")
def create_log(log: LogInput, db: Session = Depends(get_db)):
    new_event = Event(
        source_ip=log.source_ip,
        src_port=log.src_port,      # 👈 Saving the port
        honeypot_type=log.protocol,
        raw_data=log.details,
        timestamp=datetime.utcnow()
    )
    db.add(new_event)
    db.commit()
    return {"message": "log stored"}