# =========================
# CORE IMPORTS (Reloaded)
# =========================
import os
import json
import contextlib
import socket
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Union, Tuple

import psutil
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text, func
from sqlalchemy.orm import Session

# =========================
# DATABASE & MODELS
# =========================
from database.database import get_db, engine, SessionLocal
from database.models import Base, PacketLog, TrafficStats

# =========================
# INTERNAL SERVICES
# =========================
from services.traffic_sniffer import RealTimeSniffer
from services.stats_aggregator import StatsService
from services.firewall import FirewallService
from services.threat_analyzer import threat_analyzer
from services.scheduler_service import scheduler_service
from services.pcap_analyzer import pcap_analyzer
from services.geo import GeoService
from services.geoip_service import geoip_service
from services.response_executor import response_executor

# =========================
# ML ENGINE
# =========================
from ml_engine.campaign_clustering import campaign_clusterer
from ml_engine.explainability import explainer_service

# =========================
# PERFORMANCE MIDDLEWARE
# =========================
from middleware.profiling import ProfilingMiddleware
from middleware.metrics_collector import MetricsMiddleware, get_metrics_response
from middleware.cache import cache_response, api_cache
from middleware.auth import seed_default_admin
from middleware.logging_middleware import SecurityLoggingMiddleware

# =========================
# API ROUTERS
# =========================
from api.model_metrics import router as model_metrics_router
from api.threat_intel import router as threat_intel_router
from api.topology import router as topology_router
from api.management import router as management_router
from api.realtime import router as realtime_router, push_realtime_event
from api.pcap import router as pcap_router
from api.attack_attribution import router as attack_attribution_router
from api.predictive import router as predictive_router
from api.admin import router as admin_router
from api.threat_scoring import router as threat_router
from ml.threat_scoring_service import score_threat, map_score_to_level, ThreatInput, REDIS_AVAILABLE, _FEATURE_EXTRACTOR
from api.protocol_analytics import router as analytics_router
from api.metrics import router as metrics_router
from api.pattern_analytics import router as pattern_analytics_router
from api.reports import router as reports_router
from api.hunting import router as hunting_router
from api.cases import router as cases_router
from api.honeypots import get_honeypot_status

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
async def lifespan(_app: FastAPI):
    """
    Lifespan context manager for FastAPI.
    Handles startup and shutdown events.
    """
    Base.metadata.create_all(bind=engine)

    if ENVIRONMENT not in ["ci", "test"]:
        sniffer: RealTimeSniffer = RealTimeSniffer()
        sniffer.start_background_sniffer()
        print("PhantomNet Sniffer Started")

        # Start Threat Analyzer Background Service (with 2s delay)
        async def delayed_analyzer_start():
            await asyncio.sleep(2)
            try:
                threat_analyzer.start()
                print("Threat Analyzer Service started (background)")
            except Exception as e:
                print(f"Error starting threat analyzer: {e}")
        
        asyncio.create_task(delayed_analyzer_start())

        # Initialize and load scheduled reports
        scheduler_service.load_schedules()
        print("Scheduled Reports Loader Started")

        # Start Real-Time Metrics Broadcaster
        asyncio.create_task(broadcast_live_metrics())
        # Start PCAP Retention Cleanup (daily)
        asyncio.create_task(_pcap_cleanup_scheduler(pcap_analyzer))

        # Start Event Stream Broadcaster
        asyncio.create_task(broadcast_event_stream())

        # Seed default admin
        _db = SessionLocal()
        seed_default_admin(_db)
        _db.close()
    else:
        print("Sniffer disabled (CI/Test mode)")

    yield
    print("PhantomNet Shutting Down")
    threat_analyzer.stop()


async def _pcap_cleanup_scheduler(analyzer) -> None:
    """
    Background task to run PCAP retention cleanup once per day.

    Args:
        analyzer: The PCAP analyzer service instance.
    """
    while True:
        try:
            result = analyzer.cleanup_old_pcaps(retention_days=30)
            if result["removed_files"] > 0:
                print(
                    f"[Cleanup] PCAP Cleanup: Removed {result['removed_files']} expired files ({result['freed_bytes']} bytes freed)"
                )
        except Exception as e:
            print(f"PCAP cleanup error: {e}")
        await asyncio.sleep(86400)  # 24 hours


async def broadcast_live_metrics() -> None:
    """
    Background task to broadcast real-time metrics every 2 seconds via WebSockets.
    Fetches stats, enriches them with honeypot and system health data.
    """
    print("[+] Real-Time Metrics Broadcaster Started")
    while True:
        try:
            db = SessionLocal()
            service = StatsService(db)
            stats = service.calculate_stats()

            # Enrich with Honeypot Statuses
            stats["honeypots"] = get_honeypot_status()

            # Enrich with system health (use os.getcwd() for Windows compatibility)
            try:
                disk_path = os.path.splitdrive(os.getcwd())[0] + "\\" or "/"
                disk_percent = psutil.disk_usage(disk_path).percent
            except Exception:
                disk_percent = 0

            stats["system_health"] = {
                "cpu": psutil.cpu_percent(),
                "memory": psutil.virtual_memory().percent,
                "disk": disk_percent,
            }

            # Enrich with ML Status (Dynamic metrics)
            unscored_count = db.query(PacketLog).filter(PacketLog.threat_level.is_(None)).count()
            stats["ml_status"] = {
                "inference_time": f"{threat_analyzer.last_inference_ms}ms",
                "queue_depth": unscored_count,
                "status": "online" if threat_analyzer.running else "offline",
            }

            # Calculate events per minute (last 5 minutes)
            five_min_ago = datetime.utcnow() - timedelta(minutes=5)
            epm_count = (
                db.query(func.count(PacketLog.id))
                .filter(PacketLog.timestamp >= five_min_ago)
                .scalar()
                or 0
            )
            stats["events_per_minute"] = round(epm_count / 5, 1)

            await push_realtime_event("LIVE_METRICS", stats)
        except Exception as e:
            print(f"Error in metrics broadcast loop: {e}")
        finally:
            if "db" in locals():
                db.close()

        await asyncio.sleep(2)


async def broadcast_event_stream() -> None:
    """
    Background task to broadcast new events to connected clients in real-time.
    Identifies new PacketLog entries and pushes them via WebSockets.
    """

    print("🚀 Event Stream Broadcaster Started")
    last_id = 0
    while True:
        try:
            db = SessionLocal()
            query = db.query(PacketLog)
            if last_id > 0:
                query = query.filter(PacketLog.id > last_id)
            query = query.order_by(PacketLog.id.desc()).limit(5)
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
                    "timestamp": (
                        event.timestamp.isoformat() if event.timestamp else None
                    ),
                    "src_port": getattr(event, "src_port", None),
                    "country": getattr(event, "country", None) or "Unknown",
                }
                await push_realtime_event("EVENT_STREAM", payload)
                last_id = max(last_id, event.id)
        except (AttributeError, KeyError, RuntimeError, socket.error) as e:
            print(f"Error in event stream broadcast: {e}")
        finally:
            if "db" in locals():
                db.close()

        await asyncio.sleep(3)


# =========================
# APP INIT (ONLY ONE APP)
# =========================
app = FastAPI(
    title="PhantomNet API",
    version="2.0",
    description="AI-Driven Active Defense Platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Performance Middleware
app.add_middleware(ProfilingMiddleware, enable_memory_tracking=False)
app.add_middleware(MetricsMiddleware)

# Security & Audit Logging
app.add_middleware(SecurityLoggingMiddleware)


# Register Routers
app.include_router(model_metrics_router)
app.include_router(threat_intel_router)
app.include_router(topology_router)
app.include_router(management_router)
app.include_router(realtime_router)
app.include_router(pcap_router)
app.include_router(attack_attribution_router)
app.include_router(predictive_router)
app.include_router(admin_router)

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
@app.get("/api/health")
def health_check() -> dict:
    """
    Check the health of the API.
    """
    return {"status": "online", "timestamp": datetime.utcnow().isoformat()}


# =========================
# LIVE TRAFFIC
# =========================
@app.get("/analyze-traffic")
def get_real_traffic(db: Session = Depends(get_db)) -> dict:
    """
    Fetches the latest packet logs and enriches them with AI analysis results.

    Returns:
        dict: A status indicator, count of logs, and the list of enriched traffic data.
    """
    logs = db.query(PacketLog).order_by(PacketLog.timestamp.desc()).limit(50).all()

    data = []
    # Batch cache for this specific request to avoid multiple lookups for the same IP in one loop
    batch_geo_cache = {}

    for log in logs:
        # Use persistent field if available, else look up (for legacy logs)
        location = getattr(log, "country", None) or "UNKNOWN"
        if location == "UNKNOWN":
            if log.src_ip in batch_geo_cache:
                location = batch_geo_cache[log.src_ip]
            else:
                try:
                    geo_info = GeoService.get_geo_info(log.src_ip)
                    location = geo_info.get("flag", "🌐") + " " + geo_info.get("country", "Unknown")
                    batch_geo_cache[log.src_ip] = location
                except Exception:
                    location = "UNKNOWN"

        data.append(
            {
                "packet_info": {
                    "src": log.src_ip,
                    "dst": log.dst_ip,
                    "proto": log.protocol,
                    "length": log.length,
                    "location": location,
                    "city": getattr(log, "city", None),
                    "lat": getattr(log, "latitude", None),
                    "lon": getattr(log, "longitude", None),
                },
                "ai_analysis": {
                    "prediction": log.attack_type or "BENIGN",
                    "threat_score": log.threat_score or 0.0,
                    "confidence_percent": f"{int((log.threat_score or 0) * 100)}%",
                },
            }
        )

    return {"status": "success", "count": len(data), "data": data}


# =========================
# DASHBOARD STATS
# =========================
@app.get("/api/stats")
@cache_response(ttl_seconds=15)
def get_api_stats(db: Session = Depends(get_db)) -> dict:
    """
    Retrieves aggregated dashboard statistics.
    Returns a dictionary of counts and metrics for the dashboard.
    """
    service = StatsService(db)
    return service.calculate_stats()


@app.get("/metrics")
def prometheus_metrics() -> str:
    """
    Prometheus-compatible metrics endpoint.

    Returns:
        str: Metrics data in Prometheus format.
    """
    return get_metrics_response()


@app.get("/api/cache/stats")
def cache_stats() -> dict:
    """
    Return API cache statistics.
    """
    return api_cache.stats


# =========================
# EVENTS API
# =========================
@app.get("/api/events")
def get_events(
    threat: str = "ALL",
    protocol: str = "ALL",
    limit: int = 100,
    db: Session = Depends(get_db),
) -> list:
    """
    Query event logs with filtering for protocol and threat levels.

    Args:
        threat: Filter by threat category (MALICIOUS, SUSPICIOUS, BENIGN, ALL).
        protocol: Filter by network protocol.
        limit: Max number of results.
        db: Database session.

    Returns:
        list: Filtered and formatted event logs.
    """
    query = db.query(PacketLog)

    if protocol != "ALL":
        query = query.filter(PacketLog.protocol == protocol)

    if threat == "MALICIOUS":
        query = query.filter(PacketLog.threat_score >= 80)
    elif threat == "SUSPICIOUS":
        query = query.filter(PacketLog.threat_score.between(40, 79))
    elif threat == "BENIGN":
        query = query.filter(PacketLog.threat_score < 40)

    logs = query.order_by(PacketLog.timestamp.desc()).limit(limit).all()

    return [
        {
            "time": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": log.src_ip,
            "type": log.protocol,
            "port": 0,
            "threat": log.attack_type or "BENIGN",
            "score": log.threat_score or (0.0 if not log.attack_type else 15.0),
            "details": f"{log.attack_type or 'BENIGN'} traffic detected",
        }
        for log in logs
    ]


@app.get("/api/features/live")
def get_live_features(db: Session = Depends(get_db)):
    """
    Pulls the latest packet log from the database, runs it through the
    internal ML FeatureExtractor, and returns the live feature vector dict.
    """
    log = db.query(PacketLog).order_by(PacketLog.id.desc()).first()
    if not log:
        return {"eventId": "NO-DATA-001", "features": {}}

    event_dict = {
        "src_ip": log.src_ip or "0.0.0.0",
        "dst_ip": log.dst_ip or "0.0.0.0",
        "src_port": log.src_port or 0,
        "dst_port": log.dst_port or 0,
        "protocol": log.protocol or "TCP",
        "length": log.length or 0,
        "attack_type": log.attack_type or "UNKNOWN",
        "is_malicious": log.is_malicious or False,
        "threat_score": log.threat_score or 0.0,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None
    }
    
    # Run through the true backend feature extractor
    raw_features = _FEATURE_EXTRACTOR.extract_features(event_dict)
    
    features = {}
    for k, v in raw_features.items():
        v = round(v, 2) if isinstance(v, float) else v
        
        status = "normal"
        if ("score" in k and v > 50) or ("malicious" in k and v > 0.5) or ("anomaly" in k and v > 1.0):
            status = "anomalous"
            
        features[k] = {
            "label": k.replace("_", " ").title(),
            "value": v,
            "interpretation": f"Calculated value: {v}",
            "status": status
        }
        
    return {
        "eventId": f"LIVE-{log.protocol}-{log.id}",
        "features": features
    }


# =========================
# HONEYPOT STATUS (MAIN)
# =========================
async def check_service_status(host: str, port: int, protocol: str = "TCP") -> str:
    """
    Checks if a service is reachable on the given host and port.
    """
    try:
        # Async connection check
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=0.5)
        
        if protocol == "HTTP":
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            
        writer.close()
        await writer.wait_closed()
        return "active"
    except (asyncio.TimeoutError, Exception):
        return "inactive"


def _get_db_honeypot_metrics(db: Session) -> Tuple[Dict[str, str], Dict[str, int]]:
    """Helper to query last seen and packet counts from DB."""
    last_seen_map: Dict[str, str] = {}
    packet_counts: Dict[str, int] = {}
    try:
        results = (
            db.query(PacketLog.protocol, func.max(PacketLog.timestamp))
            .group_by(PacketLog.protocol)
            .all()
        )
        for protocol, last_time in results:
            if last_time:
                clean_proto = protocol.strip("'\"") if protocol else protocol
                ts_str = last_time.strftime("%Y-%m-%d %H:%M:%S")
                last_seen_map[clean_proto] = ts_str
                last_seen_map[protocol] = ts_str

        count_results = (
            db.query(PacketLog.protocol, func.count(PacketLog.id))
            .group_by(PacketLog.protocol)
            .all()
        )
        for protocol, count in count_results:
            clean_proto = protocol.strip("'\"") if protocol else protocol
            packet_counts[clean_proto] = count
            packet_counts[protocol] = count
    except Exception as e:
        print(f"Error querying honeypot metrics: {e}")
    return last_seen_map, packet_counts


def _get_last_seen_from_logs(protocol_name: str) -> Optional[str]:
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
        with open(log_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return None
            f.seek(max(0, size - 2048))
            lines = f.read().decode("utf-8", errors="ignore").strip().split("\n")

        for line in reversed(lines):
            if line.strip():
                try:
                    entry = json.loads(line.strip())
                    return entry.get("timestamp")
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Error reading log for {protocol_name}: {e}")
    return None


@app.get("/api/honeypots/status")
async def honeypot_status(db: Session = Depends(get_db)) -> list:
    """Returns real-time status of honeypots concurrently."""
    is_local = any(env in ENVIRONMENT.lower() for env in ["local", "development", "dev"])
    last_seen_db, packet_counts = _get_db_honeypot_metrics(db)

    services: List[Dict[str, Any]] = [
        {"name": "SSH", "port": 2222, "proto": "SSH", "host": "phantomnet_ssh"},
        {"name": "HTTP", "port": 8080, "proto": "HTTP", "host": "phantomnet_http"},
        {"name": "FTP", "port": 2121, "proto": "FTP", "host": "phantomnet_ftp"},
        {"name": "SMTP", "port": 2525, "proto": "SMTP", "host": "phantomnet_smtp"},
    ]

    # Concurrent Status Checks
    async def get_full_status(svc):
        host = "127.0.0.1" if is_local else str(svc["host"])
        status_task = check_service_status(host, int(svc["port"]), str(svc["proto"]))
        
        # Resolve Last Seen from Disk (synchronous but IO based, could be improved later)
        last_seen = _get_last_seen_from_logs(svc["proto"])
        if last_seen:
            last_seen = last_seen.replace("T", " ").split(".")[0]
        else:
            last_seen = last_seen_db.get(svc["proto"]) or last_seen_db.get(svc["proto"].lower()) or "Never"

        status = await status_task
        p_count = packet_counts.get(svc["proto"], 0) or packet_counts.get(svc["proto"].lower(), 0)
        return {
            "name": svc["name"],
            "port": svc["port"],
            "status": status,
            "last_seen": last_seen,
            "packet_count": p_count,
            "total_events": p_count, # Alias for frontend components
        }

    return await asyncio.gather(*(get_full_status(s) for s in services))


# 🔹 ALIAS SO FRONTEND /api/honeypots ALSO WORKS
@app.get("/api/honeypots")
async def honeypot_status_alias(db: Session = Depends(get_db)) -> list:
    """
    Alias for honeypot status to support multiple frontend paths.
    """
    return await honeypot_status(db)


# =========================
# ACTIVE DEFENSE
# =========================
@app.post("/active-defense/block/{ip}")
def block_ip_address(ip: str) -> dict:
    """
    Blocks a specific IP address using the firewall service.

    Args:
        ip: The IP address to block.

    Returns:
        dict: The result of the blocking operation.
    """
    if ip in ["127.0.0.1", "phantomnet_postgres", "::1"]:
        return {"status": "error", "message": "Cannot block phantomnet_postgres"}

    result = FirewallService.block_ip(ip)
    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])

    return result


# =========================
# GeoIP & ATTACK MAP
# =========================
def _process_attack_map_logs(logs: List[PacketLog]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Helper to process and aggregate attack map logs."""
    location_map: Dict[str, Dict[str, Any]] = {}
    recent_attacks: List[Dict[str, Any]] = []
    country_counts: Dict[str, int] = {}

    for log in logs:
        ip = log.src_ip
        geo = {
            "country": log.country,
            "city": log.city or "Unknown",
            "lat": log.latitude,
            "lon": log.longitude,
            "flag": geoip_service._get_flag_emoji(""),
        } if log.country and log.latitude else geoip_service.lookup(ip)

        country, city = geo.get("country", "Unknown"), geo.get("city", "Unknown")
        lat, lon = geo.get("lat", 0.0), geo.get("lon", 0.0)

        if country in ("Local Network", "Unknown") and lat == 0.0:
            continue

        loc_key = f"{country}|{city}"
        if loc_key not in location_map:
            location_map[loc_key] = {
                "country": country, "city": city, "lat": lat, "lon": lon,
                "flag": geo.get("flag", "🌐"), "count": 0, "protocols": set(), "threat_scores": [],
            }

        location_map[loc_key]["count"] += 1
        if log.protocol:
            location_map[loc_key]["protocols"].add(log.protocol)
        if log.threat_score:
            location_map[loc_key]["threat_scores"].append(log.threat_score)

        if len(recent_attacks) < 50:
            recent_attacks.append({
                "id": log.id, "src_ip": ip, "protocol": log.protocol,
                "threat_score": log.threat_score or 0.0, "threat_level": log.threat_level or "LOW",
                "country": country, "city": city, "lat": lat, "lon": lon,
                "flag": geo.get("flag", "🌐"), "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            })

        country_counts[country] = country_counts.get(country, 0) + 1

    # Finalize locations
    locations = []
    for loc in location_map.values():
        scores = loc["threat_scores"]
        locations.append({
            "country": loc["country"], "city": loc["city"], "lat": loc["lat"], "lon": loc["lon"],
            "flag": loc["flag"], "count": loc["count"], "protocols": list(loc["protocols"]),
            "avg_threat_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
        })
    locations.sort(key=lambda x: x["count"], reverse=True)
    
    top_countries = sorted([{"country": k, "count": v} for k, v in country_counts.items()],
                           key=lambda x: int(x["count"]), reverse=True)[:10] # type: ignore

    return locations, recent_attacks, top_countries


@app.get("/api/analytics/attack-map")
def get_attack_map(limit: int = 200, db: Session = Depends(get_db)) -> dict:
    """Returns geo-enriched attack data for map visualization."""
    logs = db.query(PacketLog).filter(PacketLog.src_ip.isnot(None))\
             .order_by(PacketLog.timestamp.desc()).limit(limit).all()

    locations, recent_attacks, top_countries = _process_attack_map_logs(logs)

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
def geoip_lookup(ip: str) -> dict:
    """Look up geolocation for a single IP address."""
    result = geoip_service.lookup(ip)
    return {"ip": ip, "geo": result}


@app.get("/api/geoip/status")
def geoip_status() -> dict:
    """Return GeoIP service health status."""
    return geoip_service.stats


# =========================
# AUTOMATED RESPONSE
# =========================
@app.get("/api/response/history")
def response_history(limit: int = 50) -> dict:
    """View response action audit log."""
    return {
        "status": "success",
        "count": min(limit, len(response_executor.response_history)),
        "history": response_executor.get_history(limit),
    }


@app.get("/api/response/blocked-ips")
def blocked_ips() -> dict:
    """List currently blocked IPs."""
    blocked = response_executor.get_blocked_ips()
    return {
        "status": "success",
        "count": len(blocked),
        "blocked_ips": blocked,
    }


@app.post("/api/response/unblock/{ip}")
def unblock_ip(ip: str) -> dict:
    """Manually unblock an IP address."""
    result = response_executor.unblock_ip(ip)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail=f"IP {ip} is not blocked")
    return result


@app.get("/api/response/policy")
def get_response_policy() -> dict:
    """View current automated response policy."""
    return {
        "status": "success",
        "policy": response_executor.get_policy(),
    }


@app.put("/api/response/policy")
def update_response_policy(updates: dict) -> dict:
    """Update response policy thresholds."""
    updated = response_executor.update_policy(updates)
    return {
        "status": "success",
        "policy": updated,
    }


@app.get("/api/response/stats")
def response_stats() -> dict:
    """Return automated response system statistics."""
    return response_executor.stats


# =========================
# ADVANCED ML ENDPOINTS
# =========================
@app.get("/api/v1/advanced/campaigns", tags=["Advanced ML"])
def get_attack_campaigns(hours_back: int = 24, db: Session = Depends(get_db)) -> dict:
    """Analyze recent threats and cluster coordinated attack campaigns."""
    result = campaign_clusterer.identify_campaigns(hours_back)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result


@app.get("/api/v1/events/{event_id}/explanation", tags=["Advanced ML"])
def explain_threat_score(event_id: int, db: Session = Depends(get_db)) -> dict:
    """Generate SHAP feature explanations for a specific scored event."""
    log = db.query(PacketLog).filter(PacketLog.id == event_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Event not found")

    event_data = {
        "src_ip": log.src_ip,
        "dst_ip": log.dst_ip or "127.0.0.1",
        "dst_port": log.dst_port or 0,
        "protocol": log.protocol or "UNKNOWN",
        "length": log.length or 0,
    }

    explanation = explainer_service.explain_prediction(event_data)
    if "error" in explanation:
        raise HTTPException(status_code=500, detail=explanation["error"])

    return {
        "event_id": event_id,
        "threat_level": log.threat_level,
        "score": log.threat_score,
        "explanation": explanation,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
