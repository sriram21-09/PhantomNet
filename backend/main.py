from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database.models import Base, Event
from schemas import EventCreate, EventResponse
from typing import List

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="PhantomNet API")

# --- 1. ENABLE CORS (Frontend Permission) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], # Allow your React app
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

# --- 2. ROOT ROUTE ---
@app.get("/")
def read_root():
    return {"status": "PhantomNet Backend is active"}

# --- 3. EVENTS ROUTE (This was missing!) ---
@app.get("/events/", response_model=List[EventResponse])
def read_events(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    # Get events, newest first
    events = db.query(Event).order_by(desc(Event.id)).offset(skip).limit(limit).all()
    return events