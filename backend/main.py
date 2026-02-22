# =========================
# CORE IMPORTS
# =========================
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text, func
from sqlalchemy.orm import sessionmaker, Session
import os
import json
import contextlib
import socket
from datetime import datetime
from dotenv import load_dotenv

# ... (Previous imports remain, but I need to make sure I don't delete them if they are in the range)
# The user wants to Replace lines 4-216 (huge chunk) or I can do it in smaller chunks. 
# The file is 230 lines. 
# Let's target the Import section first, then the Endpoint.

# Wait, I can't easily replace disjoint blocks with `replace_file_content`.
# usage: "Use this tool ONLY when you are making a SINGLE CONTIGUOUS block of edits".
# So I should use `multi_replace_file_content` or just replace the specific parts.

# Let's use `multi_replace_file_content`.

# =========================
# INTERNAL SERVICES
# =========================
from services.traffic_sniffer import RealTimeSniffer
from services.stats_aggregator import StatsService
from services.firewall import FirewallService
from services.threat_analyzer import threat_analyzer

# =========================
# MODELS
# =========================
from database.models import Base, PacketLog, TrafficStats

# =========================
# API ROUTERS
# =========================
from api.model_metrics import router as model_metrics_router

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
# LIFESPAN
# =========================
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    if ENVIRONMENT not in ["ci", "test"]:
        sniffer = RealTimeSniffer()
        sniffer.start_background_sniffer()
        print("PhantomNet Sniffer Started")
        
        # Start Threat Analyzer Background Service
        threat_analyzer.start()
    else:
        print("Sniffer disabled (CI/Test mode)")

    yield
    print("PhantomNet Shutting Down")
    threat_analyzer.stop()

# =========================
# APP INIT (ONLY ONE APP)
# =========================
app = FastAPI(
    title="PhantomNet API",
    version="2.0",
    description="AI-Driven Active Defense Platform",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(model_metrics_router)

# =========================
# ROUTERS
# =========================
from api.threat_scoring import router as threat_router
from api.protocol_analytics import router as analytics_router
from api.metrics import router as metrics_router

app.include_router(threat_router)
app.include_router(analytics_router)
app.include_router(metrics_router)

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
# LIVE TRAFFIC
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
        # Use persistent field if available, else look up (for legacy logs)
        location = log.country or "UNKNOWN"
        if location == "UNKNOWN":
            try:
                from services.geo import GeoService
                geo = GeoService.get_geo_info(log.src_ip)
                location = geo.get("flag", "🌐") + " " + geo.get("country", "Unknown")
            except:
                location = "UNKNOWN"

        data.append({
            "packet_info": {
                "src": log.src_ip,
                "dst": log.dst_ip,
                "proto": log.protocol,
                "length": log.length,
                "location": location,
                "city": log.city,
                "lat": log.latitude,
                "lon": log.longitude
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
# DASHBOARD STATS
# =========================
@app.get("/api/stats")
def get_api_stats(db: Session = Depends(get_db)):
    service = StatsService(db)
    return service.calculate_stats()

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
# HONEYPOT STATUS (MAIN)
# =========================
def check_service_status(host, port, protocol="TCP"):
    """
    Checks if a service is reachable on the given host and port.
    Returns 'active' if reachable, 'inactive' otherwise.
    For HTTP, sends a byte to ensure the server acknowledges it as a request (logging side effect).
    """
    try:
        # Timeout is short (0.5s) to avoid UI hanging
        with socket.create_connection((host, port), timeout=0.5) as sock:
            if protocol == "HTTP":
                # Send a basic request to trigger the honeypot logger
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            return "active"
    except (socket.timeout, socket.error):
        return "inactive"

@app.get("/api/honeypots/status")
def honeypot_status(db: Session = Depends(get_db)):
    """
    Returns real-time status of honeypots by checking:
    1. Container connectivity (via socket)
    2. Last seen activity (via DB logs)
    """
    
    # 1. Determine Hostnames based on Environment
    # If running in Docker (default), use service names.
    # If running locally (dev), use phantomnet_postgres.
    is_local = any(env in ENVIRONMENT.lower() for env in ["local", "development", "dev"])
    
    services = [
        {"name": "SSH",  "port": 2222, "protocol": "SSH",  "host_docker": "phantomnet_ssh"},
        {"name": "HTTP", "port": 8080, "protocol": "HTTP", "host_docker": "phantomnet_http"},
        {"name": "FTP",  "port": 2121, "protocol": "FTP",  "host_docker": "phantomnet_ftp"},
        {"name": "SMTP", "port": 2525, "protocol": "SMTP", "host_docker": "phantomnet_smtp"},
    ]
    
    # 2. Query Last Seen Timestamps from DB
    # Try to get max timestamp per protocol (including variations)
    last_seen_map = {}
    packet_counts = {}  # Initialize before try block
    try:
        results = db.query(
            PacketLog.protocol, 
            func.max(PacketLog.timestamp)
        ).group_by(PacketLog.protocol).all()
        
        for protocol, last_time in results:
            if last_time:
                # Store with cleaned protocol name (strip quotes if present)
                clean_proto = protocol.strip("'\"") if protocol else protocol
                last_seen_map[clean_proto] = last_time.strftime("%Y-%m-%d %H:%M:%S")
                # Also store original for direct lookup
                last_seen_map[protocol] = last_time.strftime("%Y-%m-%d %H:%M:%S")
                
        # Query packet counts
        packet_counts = {}
        count_results = db.query(
            PacketLog.protocol,
            func.count(PacketLog.id)
        ).group_by(PacketLog.protocol).all()
        
        for protocol, count in count_results:
            clean_proto = protocol.strip("'\"") if protocol else protocol
            packet_counts[clean_proto] = count
            packet_counts[protocol] = count
            
    except Exception as e:
        print(f"Error querying last seen/counts: {e}")

    # Helper to read last timestamp from honeypot log files
    def get_last_seen_from_logs(protocol_name):
        """Read last activity timestamp from honeypot log files"""
        log_files = {
            "SSH": "logs/ssh.jsonl",
            "HTTP": "logs/http_logs.jsonl",
            "FTP": "logs/ftp_logs.jsonl",
            "SMTP": "logs/smtp_logs.jsonl",
        }
        
        log_file = log_files.get(protocol_name.upper())
        if not log_file:
            return None
            
        log_path = os.path.join(os.path.dirname(__file__), log_file)
        
        if not os.path.exists(log_path):
            return None
            
        try:
            # Read last line of the log file
            with open(log_path, 'rb') as f:
                f.seek(0, 2)  # Go to end
                size = f.tell()
                if size == 0:
                    return None
                # Read last 2KB or entire file
                f.seek(max(0, size - 2048))
                lines = f.read().decode('utf-8', errors='ignore').strip().split('\n')
                
            # Parse the last valid JSON line
            for line in reversed(lines):
                if line.strip():
                    try:
                        entry = json.loads(line.strip())
                        timestamp = entry.get("timestamp")
                        if timestamp:
                            return timestamp
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading log for {protocol_name}: {e}")
        
        return None

    # Helper to find last_seen with fallback
    def get_last_seen(protocol_name):
        # First try to get from log files (most accurate)
        log_timestamp = get_last_seen_from_logs(protocol_name)
        if log_timestamp:
            # Log files contain ISO format timestamps
            return log_timestamp.replace("T", " ").split(".")[0]  # Convert to readable format
        
        # Fallback to database
        if protocol_name in last_seen_map:
            return last_seen_map[protocol_name]
        if protocol_name.lower() in last_seen_map:
            return last_seen_map[protocol_name.lower()]
        if protocol_name.upper() in last_seen_map:
            return last_seen_map[protocol_name.upper()]
        return "Never"
    
    def get_packet_count(protocol_name):
        if protocol_name in packet_counts:
            return packet_counts[protocol_name]
        if protocol_name.lower() in packet_counts:
            return packet_counts[protocol_name.lower()]
        if protocol_name.upper() in packet_counts:
            return packet_counts[protocol_name.upper()]
        return 0

    # 3. Build Response
    data = []
    for svc in services:
        # Determine target host
        host = "127.0.0.1" if is_local else svc["host_docker"]
        
        # Check Socket
        status = check_service_status(host, svc["port"], svc["protocol"])
        
        # Get Last Seen - use helper with fallback
        last_seen = get_last_seen(svc["protocol"])
        
        # Get Packet Count using helper
        pkt_count = get_packet_count(svc["protocol"])
        
        data.append({
            "name": svc["name"],
            "port": svc["port"],
            "status": status,
            "last_seen": last_seen,
            "packet_count": pkt_count
        })
        
    return data

# 🔹 ALIAS SO FRONTEND /api/honeypots ALSO WORKS
@app.get("/api/honeypots")
def honeypot_status_alias(db: Session = Depends(get_db)):
    return honeypot_status(db)

# =========================
# ACTIVE DEFENSE
# =========================
@app.post("/active-defense/block/{ip}")
def block_ip_address(ip: str):
    if ip in ["127.0.0.1", "phantomnet_postgres", "::1"]:
        return {"status": "error", "message": "Cannot block phantomnet_postgres"}

    result = FirewallService.block_ip(ip)
    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])

    return result
