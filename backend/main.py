from services.geo import GeoService

# =========================
# CORE IMPORTS
# =========================
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
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
from services.firewall import FirewallService

# =========================
# MODELS
# =========================
from app_models import Base, PacketLog, TrafficStats

# =========================
# ENVIRONMENT SETUP
# =========================
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("⚠️ WARNING: DATABASE_URL not set. Using local sqlite DB.")
    DATABASE_URL = "sqlite:///./phantomnet.db"

# =========================
# DATABASE SETUP
# =========================
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

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
# LIFESPAN
# =========================
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    sniffer = RealTimeSniffer()
    sniffer.start_background_sniffer()
    print("🚀 PhantomNet Sniffer Started")
    yield
    print("🛑 PhantomNet Shutting Down")

# =========================
# APP INIT
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
# CORE ENDPOINTS
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
# DASHBOARD LIVE FEED
# =========================
@app.get("/analyze-traffic")
def get_real_traffic(db: Session = Depends(get_db)):
    logs = (
        db.query(PacketLog)
        .order_by(PacketLog.timestamp.desc())
        .limit(50)
        .all()
    )

    data = []

    for log in logs:
        data.append({
            "packet_info": {
                "src": log.src_ip,
                "dst": log.dst_ip,
                "proto": log.protocol,
                "length": log.length,
                "location": GeoService.get_country(log.src_ip)
            },
            "ai_analysis": {
                "prediction": log.attack_type or "BENIGN",
                "threat_score": log.threat_score,
                "confidence_percent": f"{int(log.threat_score * 100)}%"
            }
        })

    return {
        "status": "success",
        "data": data
    }

# =========================
# DASHBOARD STATS
# =========================
@app.get("/api/stats")
def get_api_stats(db: Session = Depends(get_db)):
    service = StatsService(db)
    stats = service.calculate_stats()

    return {
        "totalEvents": stats.total_attacks,
        "uniqueIPs": stats.unique_attackers,
        "activeHoneypots": len(json.loads(stats.attacks_by_type or "{}")),
        "avgThreatScore": 0,
        "criticalAlerts": 0
    }

# =========================
# EVENTS API
# =========================
@app.get("/api/events")
def get_events(
    threat: str = "ALL",
    protocol: str = "ALL",
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(PacketLog)

    if threat != "ALL":
        query = query.filter(PacketLog.attack_type == threat)

    if protocol != "ALL":
        query = query.filter(PacketLog.protocol == protocol)

    logs = (
        query
        .order_by(PacketLog.timestamp.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "time": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": log.src_ip,
            "type": log.protocol,
            "port": 0,
            "threat": log.attack_type or "BENIGN",
            "details": f"{log.attack_type or 'BENIGN'} traffic detected"
        }
        for log in logs
    ]

# =========================
# ACTIVE DEFENSE
# =========================
@app.post("/active-defense/block/{ip}")
def block_ip_address(ip: str):
    if ip in ["127.0.0.1", "localhost", "::1"]:
        return {"status": "error", "message": "Cannot block localhost"}

    result = FirewallService.block_ip(ip)
    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])

    return result
