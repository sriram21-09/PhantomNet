from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from typing import List

from database.models import Base, Event
from schemas import EventCreate, EventResponse

# =========================
# DATABASE CONFIGURATION
# =========================

DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# =========================
# FASTAPI APP INIT
# =========================

app = FastAPI(title="PhantomNet API")

# =========================
# CORS CONFIG (Frontend Access)
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
# ROOT ENDPOINT
# =========================

@app.get("/")
def read_root():
    return {"status": "PhantomNet Backend is active"}

# =========================
# FETCH EVENTS
# =========================

@app.get("/events", response_model=List[EventResponse])
def read_events(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    events = (
        db.query(Event)
        .order_by(desc(Event.id))
        .offset(skip)
        .limit(limit)
        .all()
    )
    return events
