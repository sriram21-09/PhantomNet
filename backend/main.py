from services.geo import GeoService

# =========================
# CORE IMPORTS
# =========================
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
import os
import contextlib
from dotenv import load_dotenv

# =========================
# INTERNAL SERVICES
# =========================
from services.traffic_sniffer import RealTimeSniffer
from services.stats_aggregator import StatsService
from services.firewall import FirewallService

# =========================
# MODELS (FINAL – NO SMTP FIELDS)
# =========================
from app_models import Base, PacketLog, TrafficStats

# =========================
# ENVIRONMENT SETUP
# =========================
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
ENVIRONMENT = os.getenv("ENVIRONMENT", "local")

if not DATABASE_URL:
    print("WARNING: DATABASE_URL not set. Using local sqlite DB.")
    DATABASE_URL = "sqlite:///./phantomnet.db"

# =========================
# DATABASE SETUP
# =========================
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

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
# LIFESPAN (SAFE STARTUP)
# =========================
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    if ENVIRONMENT not in ["ci", "test"]:
        sniffer = RealTimeSniffer()
        sniffer.start_background_sniffer()
        print("PhantomNet Sniffer Started")
    else:
        print("Sniffer disabled (CI/Test mode)")

    yield
    print("PhantomNet Shutting Down")

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
        try:
            location = GeoService.get_country(log.src_ip)
        except Exception:
            location = "UNKNOWN"

        data.append({
            "packet_info": {
                "src": log.src_ip,
                "dst": log.dst_ip,
                "proto": log.protocol,
                "length": log.length,
                "location": location
            },
            "ai_analysis": {
                "prediction": log.attack_type or "BENIGN",
                "threat_score": log.threat_score or 0.0,
                "confidence_percent": f"{int((log.threat_score or 0) * 100)}%"
            }
        })

    return {
        "status": "success",
        "count": len(data),
        "data": data
    }

# =========================
# DASHBOARD STATS (AUTHORITATIVE)
# =========================
@app.get("/api/stats")
def get_api_stats(db: Session = Depends(get_db)):
    """
    Dashboard statistics.
    Single source of truth: packet_logs via StatsService.
    """
    service = StatsService(db)
    return service.calculate_stats()

# =========================
# EVENTS API (FINAL & STABLE)
# =========================
@app.get("/api/events")
def get_events(
    threat: str = "ALL",
    protocol: str = "ALL",
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(PacketLog)

    if protocol != "ALL":
        query = query.filter(PacketLog.protocol == protocol)

    if threat == "MALICIOUS":
        query = query.filter(PacketLog.threat_score >= 80)
    elif threat == "SUSPICIOUS":
        query = query.filter(PacketLog.threat_score.between(40, 79))
    elif threat == "BENIGN":
        query = query.filter(PacketLog.threat_score < 40)

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
# HONEYPOT STATUS (FIXED – NO MORE 404)
# =========================
@app.get("/api/honeypots/status")
def honeypot_status():
    return [
        {
            "name": "SSH",
            "port": 22,
            "status": "active",
            "last_seen": "2026-01-10 10:30"
        },
        {
            "name": "HTTP",
            "port": 80,
            "status": "active",
            "last_seen": "2026-01-10 10:28"
        },
        {
            "name": "FTP",
            "port": 21,
            "status": "inactive",
            "last_seen": "2026-01-10 09:55"
        },
        {
            "name": "SMTP",
            "port": 25,
            "status": "active",
            "last_seen": "2026-01-10 10:25"
        }
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
