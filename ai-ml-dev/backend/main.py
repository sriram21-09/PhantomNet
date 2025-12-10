from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, Event
from schemas import EventCreate, EventResponse
from typing import List

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# THIS IS THE MISSING VARIABLE 'app'
app = FastAPI(title="PhantomNet API")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"status": "PhantomNet Backend is active"}

@app.get("/events/", response_model=List[EventResponse])
def read_events(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    events = db.query(Event).offset(skip).limit(limit).all()
    return events