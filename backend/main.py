from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
from datetime import datetime

# Import our custom modules
from database.models import Base, Event
from database.database import SessionLocal, engine
from utils.normalizer import normalize_log

# Create Tables
Base.metadata.create_all(bind=engine)

# Initialize the App
app = FastAPI()

# Setup Security (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"],
)

# Database Dependency
def get_db():
    db = SessionLocal()
    try: 
        yield db
    finally: 
        db.close()

# --- GET ENDPOINTS ---

@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    return db.query(Event).order_by(Event.timestamp.desc()).limit(50).all()

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Event.id)).scalar()
    unique = db.query(func.count(distinct(Event.source_ip))).scalar()
    return {"total_events": total, "unique_ips": unique}

# --- POST ENDPOINT (The one we just updated) ---

@app.post("/api/logs")
def create_log(payload: Dict[Any, Any], db: Session = Depends(get_db)):
    # 1. Clean the messy data using our new utility
    clean_data = normalize_log(payload)

    # 2. Save the clean data
    new_event = Event(
        source_ip=clean_data["source_ip"],
        src_port=clean_data["src_port"],
        honeypot_type=clean_data["protocol"],
        raw_data=clean_data["details"],
        timestamp=datetime.utcnow()
    )
    db.add(new_event)
    db.commit()
    return {"message": "log normalized and stored"}