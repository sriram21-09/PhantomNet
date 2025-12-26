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
import json
import contextlib
from dotenv import load_dotenv

# =========================
# INTERNAL SERVICES
# =========================
from services.traffic_sniffer import RealTimeSniffer
from services.stats_aggregator import StatsService
from services.firewall import FirewallService  # Your Active Defense Service

# Models
from app_models import Base, PacketLog, TrafficStats

# =========================
# ENVIRONMENT SETUP
# =========================
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
# Fallback to local SQLite if .env is missing (Developer Friendly)
if not DATABASE_URL:
    print("⚠️  WARNING: DATABASE_URL not set. Using local sqlite file.")
    DATABASE_URL = "sqlite:///./phantomnet.db"

# =========================
# DATABASE SETUP
# =========================
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Tables (Safe to run multiple times)
Base.metadata.create_all(bind=engine)

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
# LIFESPAN (Startup/Shutdown)
# =========================
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Launch the Sniffer
    sniffer = RealTimeSniffer()
    sniffer.start_background_sniffer()
    print("🚀 PhantomNet Sniffer Started...")
    yield
    # Shutdown: Clean up if needed
    print("🛑 Shutting down...")

# =========================
# APP INITIALIZATION
# =========================
app = FastAPI(
    title="PhantomNet API",
    version="2.0",
    description="AI-Driven Active Defense Platform",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# =========================
# 1. CORE ENDPOINTS
# =========================
@app.get("/")
def read_root():
    return {"message": "PhantomNet Active Defense System: ONLINE"}

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "error", "database": str(e)}

# =========================
# 2. DASHBOARD DATA (Your Work)
# =========================

# This endpoint now fetches REAL data from the DB (Team Lead's Logic)
# But keeps the URL your Frontend expects ('/analyze-traffic')
@app.get("/analyze-traffic")
def get_real_traffic(db: Session = Depends(get_db)):
    """
    Fetches the latest 50 packets from the database for the Live Feed.
    """
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
                    "prediction": "MALICIOUS" if log.is_malicious else "BENIGN",
                    "threat_score": log.threat_score,
                    "confidence_percent": f"{int(log.threat_score * 100)}%"
                }
            }
            for log in logs
        ]
    }

@app.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Your High-Performance Statistics Engine.
    """
    service = StatsService(db)
    
    # 1. Update & Fetch Cache
    stats = service.calculate_stats()
    
    # 2. Fetch Hourly Trend
    hourly = service.get_hourly_trend()
    
    return {
        "status": "success",
        "data": {
            "total_attacks": stats.total_attacks,
            "unique_ips": stats.unique_attackers,
            "attacks_by_type": json.loads(stats.attacks_by_type),
            "hourly_trend": hourly,
            "last_updated": stats.last_updated
        }
    }

# =========================
# 3. ACTIVE DEFENSE (Kill Switch)
# =========================
@app.post("/active-defense/block/{ip}")
def block_ip_address(ip: str):
    """
    Triggers Windows Firewall to ban an IP.
    """
    # Security check: Don't block localhost
    if ip in ["127.0.0.1", "localhost", "::1"]:
        return {"status": "error", "message": "Cannot block localhost!"}

    result = FirewallService.block_ip(ip)
    
    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])
    
    return result