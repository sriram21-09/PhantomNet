"""
Admin Panel API — User Management, System Config, and DB Maintenance.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from database.database import get_db, engine
from database.models import User, SystemConfig, PacketLog, Alert, Event, Base
from middleware.auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    require_role,
)
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import os
import shutil
import json
import psutil

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


# ================== Pydantic Schemas ==================


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "Viewer"


class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    status: Optional[str] = None


class ConfigUpdate(BaseModel):
    key: str
    value: str
    category: str


# ================== Auth ==================


@router.post("/login")
def admin_login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    if user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled"
        )

    user.last_login = datetime.utcnow()
    db.commit()

    token = create_access_token({"sub": user.username, "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }


# ================== User Management ==================


@router.get("/users")
def list_users(
    db: Session = Depends(get_db), _user: User = Depends(require_role("Admin"))
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "status": u.status,
                "last_login": u.last_login.isoformat() if u.last_login else None,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ]
    }


@router.post("/users")
def create_user(
    req: UserCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin")),
):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    if req.role not in ("Admin", "Analyst", "Viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")

    user = User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        role=req.role,
        status="active",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"status": "created", "user_id": user.id, "username": user.username}


@router.put("/users/{user_id}")
def update_user(
    user_id: int,
    req: UserUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin")),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if req.email is not None:
        user.email = req.email
    if req.password is not None:
        user.hashed_password = hash_password(req.password)
    if req.role is not None:
        if req.role not in ("Admin", "Analyst", "Viewer"):
            raise HTTPException(status_code=400, detail="Invalid role")
        user.role = req.role
    if req.status is not None:
        if req.status not in ("active", "disabled"):
            raise HTTPException(status_code=400, detail="Invalid status")
        user.status = req.status

    db.commit()
    return {"status": "updated", "user_id": user.id}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin")),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete default admin")

    db.delete(user)
    db.commit()
    return {"status": "deleted", "user_id": user_id}


# ================== System Configuration ==================

DEFAULT_CONFIG = [
    # Threat Detection
    {"key": "ml_threshold", "value": "0.65", "category": "threat_detection"},
    {"key": "auto_response", "value": "true", "category": "threat_detection"},
    {
        "key": "alert_email",
        "value": "admin@phantomnet.local",
        "category": "threat_detection",
    },
    {"key": "alert_severity_filter", "value": "MEDIUM", "category": "threat_detection"},
    # Honeypot
    {"key": "deception_mode", "value": "balanced", "category": "honeypot"},
    {"key": "ssh_banner", "value": "OpenSSH_8.9", "category": "honeypot"},
    {"key": "http_banner", "value": "Apache/2.4.54", "category": "honeypot"},
    {"key": "max_interaction_time", "value": "300", "category": "honeypot"},
    # SIEM
    {"key": "siem_type", "value": "none", "category": "siem"},
    {"key": "siem_endpoint", "value": "", "category": "siem"},
    {"key": "siem_export_frequency", "value": "60", "category": "siem"},
    # Performance
    {"key": "db_pool_size", "value": "10", "category": "performance"},
    {"key": "cache_ttl", "value": "300", "category": "performance"},
    {"key": "log_retention_days", "value": "90", "category": "performance"},
]


@router.get("/config")
def get_config(
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin", "Analyst")),
):
    configs = db.query(SystemConfig).all()
    if not configs:
        # Seed defaults
        for cfg in DEFAULT_CONFIG:
            db.add(SystemConfig(**cfg))
        db.commit()
        configs = db.query(SystemConfig).all()

    result = {}
    for c in configs:
        if c.category not in result:
            result[c.category] = {}
        result[c.category][c.key] = {
            "value": c.value,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        }
    return {"config": result}


@router.put("/config")
def update_config(
    req: ConfigUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin")),
):
    cfg = db.query(SystemConfig).filter(SystemConfig.key == req.key).first()
    if cfg:
        cfg.value = req.value
        cfg.category = req.category
        cfg.updated_at = datetime.utcnow()
    else:
        cfg = SystemConfig(key=req.key, value=req.value, category=req.category)
        db.add(cfg)

    db.commit()
    return {"status": "updated", "key": req.key}


# ================== System Overview ==================


@router.get("/system-overview")
def system_overview(
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin", "Analyst")),
):
    total_events = db.query(func.count(PacketLog.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_users = db.query(func.count(User.id)).scalar() or 0

    is_postgres = "postgresql" in engine.url.drivername
    if is_postgres:
        db_type = "PostgreSQL"
        try:
            db_name = engine.url.database
            size_bytes = db.execute(text("SELECT pg_database_size(:db_name)"), {"db_name": db_name}).scalar() or 0
            db_size_mb = round(size_bytes / (1024 * 1024), 2)
        except Exception:
            db_size_mb = 0.0
    else:
        db_type = "SQLite"
        db_path = os.path.abspath("phantomnet.db")
        db_size_mb = (
            round(os.path.getsize(db_path) / (1024 * 1024), 2)
            if os.path.exists(db_path)
            else 0
        )

    return {
        "system": {
            "version": "2.0.0",
            "uptime": "Running",
            "python_version": os.sys.version.split()[0],
            "db_type": db_type,
            "db_size_mb": db_size_mb,
        },
        "resources": {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "memory_used_gb": round(psutil.virtual_memory().used / (1024**3), 2),
            "disk_percent": psutil.disk_usage("/").percent,
        },
        "stats": {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "total_users": total_users,
        },
        "components": [
            {"name": "FastAPI Server", "status": "online"},
            {
                "name": f"{db_type} Database",
                "status": "online",
            },
            {"name": "ML Engine", "status": "online"},
            {"name": "Real-Time WebSocket", "status": "online"},
            {"name": "Traffic Sniffer", "status": "online"},
        ],
    }


# ================== Maintenance ==================


@router.post("/backup")
def create_backup(db: Session = Depends(get_db), _user: User = Depends(require_role("Admin"))):
    is_postgres = "postgresql" in engine.url.drivername
    backup_dir = os.path.abspath("backups")
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    if is_postgres:
        backup_file = f"phantomnet_backup_{timestamp}.json"
        backup_path = os.path.join(backup_dir, backup_file)
        try:
            data = {
                "users": [
                    {
                        "username": u.username,
                        "email": u.email,
                        "hashed_password": u.hashed_password,
                        "role": u.role,
                        "status": u.status,
                        "created_at": u.created_at.isoformat() if u.created_at else None,
                    } for u in db.query(User).all()
                ],
                "system_config": [
                    {
                        "key": c.key,
                        "value": c.value,
                        "category": c.category,
                    } for c in db.query(SystemConfig).all()
                ],
                "packet_logs": [
                    {
                        "timestamp": p.timestamp.isoformat() if p.timestamp else None,
                        "src_ip": p.src_ip,
                        "dst_ip": p.dst_ip,
                        "src_port": p.src_port,
                        "dst_port": p.dst_port,
                        "protocol": p.protocol,
                        "length": p.length,
                        "threat_score": p.threat_score,
                        "attack_type": p.attack_type,
                        "is_malicious": p.is_malicious,
                    } for p in db.query(PacketLog).order_by(PacketLog.id.desc()).limit(5000).all()
                ],
                "alerts": [
                    {
                        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                        "level": a.level,
                        "type": a.type,
                        "source_ip": a.source_ip,
                        "description": a.description,
                        "details": a.details,
                        "is_resolved": a.is_resolved,
                    } for a in db.query(Alert).all()
                ]
            }
            with open(backup_path, "w") as f:
                json.dump(data, f, indent=2)

            size_mb = round(os.path.getsize(backup_path) / (1024 * 1024), 2)
            return {
                "status": "success",
                "backup_file": backup_file,
                "size_mb": size_mb,
                "created_at": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PostgreSQL backup failed: {str(e)}")
    else:
        db_path = os.path.abspath("phantomnet.db")
        if not os.path.exists(db_path):
            raise HTTPException(status_code=404, detail="Database file not found")

        backup_file = f"phantomnet_backup_{timestamp}.db"
        backup_path = os.path.join(backup_dir, backup_file)
        shutil.copy2(db_path, backup_path)

        size_mb = round(os.path.getsize(backup_path) / (1024 * 1024), 2)
        return {
            "status": "success",
            "backup_file": backup_file,
            "size_mb": size_mb,
            "created_at": datetime.utcnow().isoformat(),
        }


@router.get("/backups")
def list_backups(_user: User = Depends(require_role("Admin"))):
    backup_dir = os.path.abspath("backups")
    if not os.path.exists(backup_dir):
        return {"backups": []}

    backups = []
    for f in sorted(os.listdir(backup_dir), reverse=True):
        if f.endswith(".db") or f.endswith(".json"):
            fp = os.path.join(backup_dir, f)
            backups.append(
                {
                    "filename": f,
                    "size_mb": round(os.path.getsize(fp) / (1024 * 1024), 2),
                    "created_at": datetime.fromtimestamp(
                        os.path.getmtime(fp)
                    ).isoformat(),
                }
            )
    return {"backups": backups}


@router.post("/vacuum")
def vacuum_db(
    db: Session = Depends(get_db), _user: User = Depends(require_role("Admin"))
):
    try:
        is_postgres = "postgresql" in engine.url.drivername
        if is_postgres:
            # PostgreSQL VACUUM runs outside transaction block using raw autocommit connection
            raw_conn = engine.raw_connection()
            raw_conn.set_isolation_level(0)  # AUTOCOMMIT
            cursor = raw_conn.cursor()
            cursor.execute("VACUUM")
            cursor.close()
            raw_conn.close()
        else:
            db.close()
            with engine.connect() as conn:
                conn.execute(text("VACUUM"))
        return {"status": "success", "message": "Database vacuumed and optimized"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/events/old")
def delete_old_events(
    days: int = 30,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin")),
):
    cutoff = datetime.utcnow() - timedelta(days=days)

    deleted_packets = db.query(PacketLog).filter(PacketLog.timestamp < cutoff).delete()
    deleted_events = db.query(Event).filter(Event.timestamp < cutoff).delete()
    deleted_alerts = db.query(Alert).filter(Alert.timestamp < cutoff).delete()

    db.commit()

    total = deleted_packets + deleted_events + deleted_alerts
    return {
        "status": "success",
        "deleted": {
            "packet_logs": deleted_packets,
            "events": deleted_events,
            "alerts": deleted_alerts,
            "total": total,
        },
        "cutoff_date": cutoff.isoformat(),
    }
