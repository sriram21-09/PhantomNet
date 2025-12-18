from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker, Session
from typing import List
from datetime import datetime
import os

from dotenv import load_dotenv

# =========================
# LOAD ENVIRONMENT VARIABLES
# =========================

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set. Please check your .env file")

# =========================
# DATABASE SETUP
# =========================

from database.models import Base, Event
from schemas import EventCreate, EventResponse

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables if they do not exist
Base.metadata.create_all(bind=engine)

# =========================
# FASTAPI APP INIT
# =========================

app = FastAPI(
    title="PhantomNet API",
    version="1.0",
    description="Backend API for PhantomNet Honeypot System"
)

# =========================
# CORS CONFIGURATION
# =========================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # React (Vite)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# DATABASE DEPENDENCY
# =========================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================
# API ROUTES
# =========================

API_PREFIX = "/api"

# -------------------------
# HEALTH CHECK
# -------------------------

@app.get(f"{API_PREFIX}/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute("SELECT 1")
        db_status = "connected"
    except Exception:
        db_status = "error"

    return {
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat()
    }

# -------------------------
# SUBMIT LOG (POST)
# -------------------------

@app.post(f"{API_PREFIX}/logs", status_code=200)
def create_log(event: EventCreate, db: Session = Depends(get_db)):
    try:
        new_event = Event(
            source_ip=event.source_ip,
            honeypot_type=event.honeypot_type,
            port=event.port,
            raw_data=event.raw_data
        )
        db.add(new_event)
        db.commit()
        db.refresh(new_event)

        return {"message": "log stored successfully"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------
# FETCH EVENTS (GET)
# -------------------------

@app.get(f"{API_PREFIX}/events", response_model=List[EventResponse])
def get_events(
    limit: int = 100,
    db: Session = Depends(get_db)
):
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 100"
        )

    events = (
        db.query(Event)
        .order_by(desc(Event.id))
        .limit(limit)
        .all()
    )

    return events
