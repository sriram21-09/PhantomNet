from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine, desc
from typing import List
from datetime import datetime
import os
from dotenv import load_dotenv

from database.models import Event
from schemas import EventResponse

# =========================
# ENV & DATABASE
# =========================

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set in .env file")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# =========================
# FASTAPI APP
# =========================

app = FastAPI(title="PhantomNet API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# DEPENDENCY
# =========================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================
# HEALTH
# =========================

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "database": "connected",
        "timestamp": datetime.utcnow()
    }

# =========================
# GET EVENTS
# =========================

@app.get("/api/events", response_model=List[EventResponse])
def read_events(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    return (
        db.query(Event)
        .order_by(desc(Event.id))
        .limit(limit)
        .all()
    )

# =========================
# POST LOG (🔥 THIS WAS MISSING)
# =========================

@app.post("/api/logs")
def ingest_log(payload: dict, db: Session = Depends(get_db)):
    try:
        event = Event(
            source_ip=payload["source_ip"],
            honeypot_type=payload["honeypot_type"],
            port=payload["port"],
            raw_data=payload["raw_data"]
        )
        db.add(event)
        db.commit()
        return {"message": "log stored successfully"}
    except KeyError:
        raise HTTPException(status_code=400, detail="invalid payload")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
