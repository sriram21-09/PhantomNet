from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
from datetime import datetime

# Import models (Note: We now import AttackSession)
from database.models import Base, Event, AttackSession
from database.database import SessionLocal, engine
from utils.normalizer import normalize_log

# Create Tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Security (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try: 
        yield db
    finally: 
        db.close()

# --- ENDPOINTS ---

@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    return db.query(Event).order_by(Event.timestamp.desc()).limit(50).all()

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Event.id)).scalar()
    unique = db.query(func.count(distinct(Event.source_ip))).scalar()
    return {"total_events": total, "unique_ips": unique}

@app.post("/api/logs")
def create_log(payload: Dict[Any, Any], db: Session = Depends(get_db)):
    clean_data = normalize_log(payload)

    # Check for existing AttackSession
    current_session = db.query(AttackSession).filter(
        AttackSession.attacker_ip == clean_data["source_ip"]
    ).order_by(AttackSession.start_time.desc()).first()

    if not current_session:
        current_session = AttackSession(
            attacker_ip=clean_data["source_ip"],
            start_time=datetime.utcnow(),
            threat_score=0.0
        )
        db.add(current_session)
        db.commit()
        db.refresh(current_session)

    new_event = Event(
        source_ip=clean_data["source_ip"],
        src_port=clean_data["src_port"],
        honeypot_type=clean_data["protocol"],
        raw_data=clean_data["details"],
        timestamp=datetime.utcnow(),
        session_id=current_session.id
    )
    
    db.add(new_event)
    db.commit()
    
    return {"message": "log stored", "session_id": current_session.id}