# =========================
# CORE IMPORTS
# =========================
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, desc, text, func
from sqlalchemy.orm import sessionmaker, Session
from typing import List
from datetime import datetime
import os
import contextlib

from dotenv import load_dotenv

# =========================
# INTERNAL SERVICES
# =========================
from services.feature_extractor import FeatureExtractor
from services.ai_predictor import ThreatDetector
from services.traffic_sniffer import RealTimeSniffer

from database.models import Base, Event
from schemas import EventCreate, EventResponse

from app_models import PacketLog

# =========================
# ENVIRONMENT SETUP
# =========================
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

print("✅ Connected DB:", DATABASE_URL)

# =========================
# DATABASE SETUP
# =========================
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

# =========================
# FASTAPI LIFESPAN (Sniffer)
# =========================
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    sniffer = RealTimeSniffer()
    sniffer.start_background_sniffer()
    yield
    # graceful shutdown (optional)

# =========================
# FASTAPI APP INIT (ONLY ONCE)
# =========================
app = FastAPI(
    title="PhantomNet API",
    version="1.0",
    description="AI-Driven Honeypot Detection Platform",
    lifespan=lifespan
)

# =========================
# CORS CONFIG
# =========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# DEPENDENCIES
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================
# SERVICES INIT
# =========================
extractor = FeatureExtractor()
detector = ThreatDetector()

API_PREFIX = "/api"

# =========================
# ROOT
# =========================
@app.get("/")
def read_root():
    return {"message": "PhantomNet Backend is Running"}

# =========================
# HEALTH CHECK
# =========================
@app.get(f"{API_PREFIX}/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        status = "connected"
    except Exception:
        status = "error"

    return {
        "status": "healthy",
        "database": status,
        "timestamp": datetime.utcnow().isoformat()
    }

# =========================
# EVENT INGESTION
# =========================
@app.post(f"{API_PREFIX}/logs")
def create_log(event: EventCreate, db: Session = Depends(get_db)):
    try:
        new_event = Event(
            source_ip=event.source_ip,
            honeypot_type=event.honeypot_type,
            port=event.port,
            raw_data=event.raw_data,
            timestamp=event.timestamp or datetime.utcnow()
        )
        db.add(new_event)
        db.commit()
        db.refresh(new_event)

        return {"message": "log stored", "event_id": new_event.id}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# =========================
# FETCH EVENTS
# =========================
@app.get(f"{API_PREFIX}/events", response_model=List[EventResponse])
def get_events(limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(Event)
        .order_by(desc(Event.id))
        .limit(limit)
        .all()
    )

# =========================
# DASHBOARD STATS
# =========================
@app.get(f"{API_PREFIX}/stats")
def get_stats(db: Session = Depends(get_db)):
    return {
        "totalEvents": db.query(func.count(Event.id)).scalar() or 0,
        "uniqueIPs": db.query(func.count(func.distinct(Event.source_ip))).scalar() or 0,
        "activeHoneypots": db.query(func.count(func.distinct(Event.honeypot_type))).scalar() or 0,
        "avgThreatScore": 0,      # Week-3 ML aggregation
        "criticalAlerts": 0
    }

# =========================
# AI TRAFFIC ANALYSIS (ML)
# =========================
@app.get("/analyze-traffic")
def analyze_traffic():
    samples = extractor.generate_labeled_sample()
    results = []

    for sample in samples:
        duration = extractor.extract_time_features(sample["start"], sample["end"])
        norm_dur = extractor.normalize(duration, "duration")
        proto_vec = extractor.encode_protocol(sample["proto"])
        ip_vec = extractor.extract_ip_patterns(sample["src"], sample["dst"])

        features = [norm_dur, ip_vec[0], ip_vec[1]] + proto_vec
        label, score = detector.predict(features)

        results.append({
            "packet": sample,
            "prediction": label,
            "threat_score": score,
            "confidence": f"{score * 100:.2f}%"
        })

    return {"status": "success", "results": results}

# =========================
# REAL-TIME SNIFFER DATA
# =========================
@app.get("/analyze-realtime")
def get_real_traffic(db: Session = Depends(get_db)):
    logs = (
        db.query(PacketLog)
        .order_by(PacketLog.timestamp.desc())
        .limit(50)
        .all()
    )

    return {
        "status": "success",
        "data": [
            {
                "packet_info": {
                    "src": log.src_ip,
                    "dst": log.dst_ip,
                    "proto": log.protocol,
                    "length": log.length
                },
                "ai_analysis": {
                    "prediction": log.attack_type,
                    "threat_score": log.threat_score,
                    "confidence_percent": f"{log.threat_score * 100:.1f}%"
                }
            }
            for log in logs
        ]
    }
