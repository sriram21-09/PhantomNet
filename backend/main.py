# =========================
# CORE IMPORTS
# =========================
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import contextlib
import socket
import asyncio
from sqlalchemy import text, func
from datetime import datetime
from dotenv import load_dotenv

from sqlalchemy.orm import Session
from database.database import get_db, engine
from database.models import Base, PacketLog, TrafficStats

# =========================
# INTERNAL SERVICES
# =========================
from services.traffic_sniffer import RealTimeSniffer
from services.stats_aggregator import StatsService
from services.firewall import FirewallService
from services.threat_analyzer import threat_analyzer

# =========================
# PERFORMANCE MIDDLEWARE
# =========================
from middleware.profiling import ProfilingMiddleware
from middleware.metrics_collector import MetricsMiddleware, get_metrics_response
from middleware.cache import cache_response, api_cache

# =========================
# MODELS
# =========================
# (Already imported above)

# =========================
# API ROUTERS
# =========================
from api.model_metrics import router as model_metrics_router
from api.threat_intel import router as threat_intel_router
from api.topology import router as topology_router
from api.management import router as management_router
from api.realtime import router as realtime_router, push_realtime_event
from api.attack_attribution import router as attack_attribution_router
from api.predictive import router as predictive_router

# =========================
# ENVIRONMENT SETUP
# =========================
load_dotenv()
ENVIRONMENT = os.getenv("ENVIRONMENT", "local")

# =========================
# DATABASE SETUP
# =========================
# (Already handled in database/database.py)

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

        # Initialize and load scheduled reports
        from services.scheduler_service import scheduler_service
        scheduler_service.load_schedules()
        print("Scheduled Reports Loader Started")
        
        # Start Real-Time Metrics Broadcaster
        asyncio.create_task(broadcast_live_metrics())
        
        # Start Event Stream Broadcaster
        asyncio.create_task(broadcast_event_stream())
    else:
        print("Sniffer disabled (CI/Test mode)")

    yield
    print("PhantomNet Shutting Down")
    threat_analyzer.stop()

async def broadcast_live_metrics():
    """Background task to broadcast real-time metrics every 2 seconds."""
    from database.database import SessionLocal
    from services.stats_aggregator import StatsService
    import psutil
    
    print("🚀 Real-Time Metrics Broadcaster Started")
    while True:
        try:
            db = SessionLocal()
            service = StatsService(db)
            stats = service.calculate_stats()
            
            # Enrich with Honeypot Statuses
            from api.honeypots import get_honeypot_status
            stats["honeypots"] = get_honeypot_status()
            
            # Enrich with system health
            stats["system_health"] = {
                "cpu": psutil.cpu_percent(),
                "memory": psutil.virtual_memory().percent,
                "disk": psutil.disk_usage('/').percent
            }
            
            # Enrich with ML Status (Mock/Placeholder for now as requested)
            stats["ml_status"] = {
                "inference_time": "12ms",
                "queue_depth": 0,
                "status": "online"
            }
            
            # Calculate events per minute (last 5 minutes)
            from sqlalchemy import func as sqla_func
            five_min_ago = datetime.utcnow() - __import__('datetime').timedelta(minutes=5)
            epm_count = db.query(sqla_func.count(PacketLog.id)).filter(
                PacketLog.timestamp >= five_min_ago
            ).scalar() or 0
            stats["events_per_minute"] = round(epm_count / 5, 1)
            
            await push_realtime_event("LIVE_METRICS", stats)
        except Exception as e:
            print(f"Error in metrics broadcast loop: {e}")
        finally:
            if 'db' in locals():
                db.close()
        
        await asyncio.sleep(2)


async def broadcast_event_stream():
    """Background task to broadcast new events to connected clients."""
    from database.database import SessionLocal
    
    print("🚀 Event Stream Broadcaster Started")
    last_id = 0
    while True:
        try:
            db = SessionLocal()
            query = db.query(PacketLog).order_by(PacketLog.id.desc()).limit(5)
            if last_id > 0:
                query = query.filter(PacketLog.id > last_id)
            
            new_events = query.all()
            
            for event in reversed(new_events):
                payload = {
                    "id": event.id,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "protocol": event.protocol,
                    "length": event.length,
                    "threat_score": event.threat_score or 0,
                    "threat_level": event.threat_level or "LOW",
                    "attack_type": event.attack_type or "BENIGN",
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "src_port": getattr(event, 'src_port', None),
                    "country": event.country or "Unknown",
                }
                await push_realtime_event("EVENT_STREAM", payload)
                last_id = max(last_id, event.id)
        except Exception as e:
            print(f"Error in event stream broadcast: {e}")
        finally:
            if 'db' in locals():
                db.close()
        
        await asyncio.sleep(3)

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

# Performance Middleware
app.add_middleware(ProfilingMiddleware, enable_memory_tracking=False)
app.add_middleware(MetricsMiddleware)

# Register Routers
app.include_router(model_metrics_router)
app.include_router(threat_intel_router)
app.include_router(topology_router)
app.include_router(management_router)
app.include_router(realtime_router)
app.include_router(attack_attribution_router)
app.include_router(predictive_router)

# =========================
# ROUTERS
# =========================
from api.threat_scoring import router as threat_router
from api.protocol_analytics import router as analytics_router
from api.metrics import router as metrics_router
from api.pattern_analytics import router as pattern_analytics_router
from api.reports import router as reports_router
from api.hunting import router as hunting_router
from api.cases import router as cases_router

app.include_router(threat_router)
app.include_router(analytics_router)
app.include_router(metrics_router)
app.include_router(pattern_analytics_router)
app.include_router(reports_router)
app.include_router(hunting_router)
app.include_router(cases_router)

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
@cache_response(ttl_seconds=15)
def get_api_stats(db: Session = Depends(get_db)):
    service = StatsService(db)
    return service.calculate_stats()

@app.get("/metrics")
def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    return get_metrics_response()

@app.get("/api/cache/stats")
def cache_stats():
    """Return API cache statistics."""
    return api_cache.stats

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

# =========================
# GeoIP & ATTACK MAP
# =========================
from services.geoip_service import geoip_service

@app.get("/api/analytics/attack-map")
def get_attack_map(limit: int = 200, db: Session = Depends(get_db)):
    """
    Returns geo-enriched attack data for map visualization.

    Response includes:
    - locations: aggregated attack counts per country/city with coordinates
    - top_countries: top 10 attacking countries by event count
    - recent_attacks: latest geo-enriched events for live map markers
    - service_status: GeoIP service health info
    """
    # 1. Query recent attack events with geo data
    logs = (
        db.query(PacketLog)
        .filter(PacketLog.src_ip.isnot(None))
        .order_by(PacketLog.timestamp.desc())
        .limit(limit)
        .all()
    )

    # 2. Build geo-enriched location aggregations
    location_map = {}  # key: "country|city" → {count, lat, lon, ...}
    recent_attacks = []

    for log in logs:
        ip = log.src_ip

        # Use stored geo data if available, otherwise look up
        if log.country and log.latitude:
            geo = {
                "country": log.country,
                "city": log.city or "Unknown",
                "lat": log.latitude,
                "lon": log.longitude,
                "flag": geoip_service._get_flag_emoji(""),
            }
        else:
            geo = geoip_service.lookup(ip)

        country = geo.get("country", "Unknown")
        city = geo.get("city", "Unknown")
        lat = geo.get("lat", 0.0)
        lon = geo.get("lon", 0.0)

        # Skip internal/LAN IPs on the map
        if country in ("Local Network", "Unknown") and lat == 0.0:
            continue

        # Aggregate by location
        loc_key = f"{country}|{city}"
        if loc_key not in location_map:
            location_map[loc_key] = {
                "country": country,
                "city": city,
                "lat": lat,
                "lon": lon,
                "flag": geo.get("flag", "🌐"),
                "count": 0,
                "protocols": set(),
                "threat_scores": [],
            }

        location_map[loc_key]["count"] += 1
        if log.protocol:
            location_map[loc_key]["protocols"].add(log.protocol)
        if log.threat_score:
            location_map[loc_key]["threat_scores"].append(log.threat_score)

        # Recent attacks (last 50 for live markers)
        if len(recent_attacks) < 50:
            recent_attacks.append({
                "id": log.id,
                "src_ip": ip,
                "protocol": log.protocol,
                "threat_score": log.threat_score or 0.0,
                "threat_level": log.threat_level or "LOW",
                "country": country,
                "city": city,
                "lat": lat,
                "lon": lon,
                "flag": geo.get("flag", "🌐"),
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            })

    # 3. Finalize locations
    locations = []
    for loc in location_map.values():
        scores = loc["threat_scores"]
        locations.append({
            "country": loc["country"],
            "city": loc["city"],
            "lat": loc["lat"],
            "lon": loc["lon"],
            "flag": loc["flag"],
            "count": loc["count"],
            "protocols": list(loc["protocols"]),
            "avg_threat_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
        })

    # Sort by count descending
    locations.sort(key=lambda x: x["count"], reverse=True)

    # 4. Top attacking countries
    country_counts = {}
    for loc in locations:
        c = loc["country"]
        country_counts[c] = country_counts.get(c, 0) + loc["count"]

    top_countries = sorted(
        [{"country": k, "count": v} for k, v in country_counts.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:10]

    return {
        "status": "success",
        "total_events": len(logs),
        "total_locations": len(locations),
        "locations": locations,
        "top_countries": top_countries,
        "recent_attacks": recent_attacks,
        "service_status": geoip_service.stats,
    }


@app.get("/api/geoip/lookup/{ip}")
def geoip_lookup(ip: str):
    """Look up geolocation for a single IP address."""
    result = geoip_service.lookup(ip)
    return {"ip": ip, "geo": result}


@app.get("/api/geoip/status")
def geoip_status():
    """Return GeoIP service health status."""
    return geoip_service.stats

# =========================
# AUTOMATED RESPONSE
# =========================
from services.response_executor import response_executor

@app.get("/api/response/history")
def response_history(limit: int = 50):
    """View response action audit log."""
    return {
        "status": "success",
        "count": min(limit, len(response_executor.response_history)),
        "history": response_executor.get_history(limit),
    }


@app.get("/api/response/blocked-ips")
def blocked_ips():
    """List currently blocked IPs."""
    blocked = response_executor.get_blocked_ips()
    return {
        "status": "success",
        "count": len(blocked),
        "blocked_ips": blocked,
    }


@app.post("/api/response/unblock/{ip}")
def unblock_ip(ip: str):
    """Manually unblock an IP address."""
    result = response_executor.unblock_ip(ip)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail=f"IP {ip} is not blocked")
    return result


@app.get("/api/response/policy")
def get_response_policy():
    """View current automated response policy."""
    return {
        "status": "success",
        "policy": response_executor.get_policy(),
    }


@app.put("/api/response/policy")
def update_response_policy(updates: dict):
    """Update response policy thresholds."""
    updated = response_executor.update_policy(updates)
    return {
        "status": "success",
        "policy": updated,
    }


@app.get("/api/response/stats")
def response_stats():
    """Return automated response system statistics."""
    return response_executor.stats
