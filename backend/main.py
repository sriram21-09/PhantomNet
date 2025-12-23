from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
from db_core import engine, SessionLocal, get_db
from app_models import Base, PacketLog
from services.traffic_sniffer import RealTimeSniffer
import contextlib

# 1. Initialize Database Tables
Base.metadata.create_all(bind=engine)

# 2. Lifecycle Manager (Starts Sniffer on Startup)
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Run Sniffer
    sniffer = RealTimeSniffer()
    sniffer.start_background_sniffer()
    yield
    # Shutdown logic (optional)

app = FastAPI(lifespan=lifespan)

# 3. CORS (Allow Frontend to talk to Backend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "PhantomNet AI Running"}

@app.get("/analyze-traffic")
def get_real_traffic(db: Session = Depends(get_db)):
    """
    Returns the latest 50 packets captured by the Sniffer from the DB.
    """
    logs = db.query(PacketLog).order_by(PacketLog.timestamp.desc()).limit(50).all()
    
    results = []
    for log in logs:
        results.append({
            "packet_info": {
                "src": log.src_ip,
                "dst": log.dst_ip,
                "proto": log.protocol,
                "length": log.length
            },
            "ai_analysis": {
                "prediction": log.attack_type, # BENIGN/SUSPICIOUS/MALICIOUS
                "threat_score": log.threat_score,
                "confidence_percent": f"{log.threat_score*100:.1f}%"
            }
        })
    return {"status": "success", "data": results}