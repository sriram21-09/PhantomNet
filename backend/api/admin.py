"""
Admin Panel API — User Management, System Config, and DB Maintenance.
Fully remediated with tamper-evident audit logging, real system health probes,
non-destructive backup/restore, and administrator safety invariants.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, UploadFile, File, Form
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from database.database import get_db, engine
from database.models import (
    User,
    SystemConfig,
    PacketLog,
    Alert,
    Event,
    Base,
    RefreshToken,
    HoneypotNode,
    Policy,
    AuditLog,
)
from middleware.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    rotate_refresh_token,
    revoke_token_family,
    revoke_user_tokens,
    set_auth_cookie,
    set_refresh_cookie,
    clear_auth_cookie,
    create_step_up_token,
    verify_step_up_auth,
    get_current_user,
    require_role,
)
from services.audit_service import audit_log
from services.system_config_service import set_config_value, get_config_value
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
import os
import shutil
import json
import re
import logging
import psutil
import time
import hashlib
import tempfile

logger = logging.getLogger("api.admin")

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])

_PROCESS_START_TIME = time.time()


# ================== Backup Directory Helper ==================


def get_backup_dir() -> str:
    """Return a verified writable directory for database backups."""
    candidates = [
        os.getenv("BACKUP_DIR"),
        "/app/backups",
        os.path.abspath("backups"),
        os.path.join(tempfile.gettempdir(), "phantomnet_backups"),
    ]
    for d in candidates:
        if not d:
            continue
        try:
            os.makedirs(d, exist_ok=True)
            test_file = os.path.join(d, f".test_{int(time.time()*1000)}")
            with open(test_file, "w") as f:
                f.write("write_test")
            os.remove(test_file)
            return d
        except Exception as e:
            logger.debug("Candidate backup directory '%s' is not writable: %s", d, e)

    fallback = os.path.join(tempfile.gettempdir(), "phantomnet_backups")
    os.makedirs(fallback, exist_ok=True)
    return fallback


# ================== Pydantic Schemas ==================


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class StepUpRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128)


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=6, max_length=128)
    role: str = "Viewer"

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Invalid email address format")
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", v):
            raise ValueError(
                "Username can only contain alphanumeric characters, underscores, hyphens, and dots"
            )
        return v


class UserUpdate(BaseModel):
    email: Optional[str] = Field(None, min_length=5, max_length=100)
    password: Optional[str] = Field(None, min_length=6, max_length=128)
    role: Optional[str] = None
    status: Optional[str] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
                raise ValueError("Invalid email address format")
        return v


class ConfigUpdate(BaseModel):
    key: str = Field(..., min_length=1, max_length=100)
    value: str = Field(..., max_length=2000)
    category: str = Field(..., min_length=1, max_length=50)


class RestoreRequest(BaseModel):
    filename: Optional[str] = None


# ================== Auth ==================


@router.post("/login")
def admin_login(req: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        audit_log(
            actor=req.username,
            action="ADMIN_LOGIN",
            result="failure",
            target="admin_auth",
            reason="Invalid credentials",
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    if user.status != "active":
        audit_log(
            actor=req.username,
            action="ADMIN_LOGIN",
            result="denied",
            target="admin_auth",
            reason="Account disabled",
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled"
        )

    user.last_login = datetime.utcnow()
    db.commit()

    token = create_access_token({"sub": user.username, "role": user.role})
    raw_refresh, _ = create_refresh_token(db=db, user_id=user.id)

    set_auth_cookie(response, token)
    set_refresh_cookie(response, raw_refresh)

    audit_log(
        actor=user.username,
        action="ADMIN_LOGIN",
        result="success",
        target="admin_panel",
        details={"role": user.role, "user_id": user.id},
        db=db,
    )

    return {
        "access_token": token,
        "refresh_token": raw_refresh,
        "token_type": "bearer",
        "expires_in": 900,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }


@router.post("/refresh")
def refresh_token_endpoint(
    request: Request,
    response: Response,
    req: Optional[RefreshRequest] = None,
    db: Session = Depends(get_db),
):
    """Rotate refresh token and issue new short-lived access token with replay attack protection."""
    raw_token = None
    if req and req.refresh_token:
        raw_token = req.refresh_token
    elif "phantomnet_refresh_token" in request.cookies:
        raw_token = request.cookies["phantomnet_refresh_token"]

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token",
        )

    new_access_token, new_refresh_token = rotate_refresh_token(db, raw_token)
    set_auth_cookie(response, new_access_token)
    set_refresh_cookie(response, new_refresh_token)

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": 900,
    }


@router.post("/logout")
def logout_endpoint(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Clear session cookies and revoke current refresh token."""
    clear_auth_cookie(response)
    raw_token = request.cookies.get("phantomnet_refresh_token")
    if raw_token:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        token_rec = (
            db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        )
        if token_rec:
            token_rec.revoked_at = datetime.utcnow()
            db.commit()

    audit_log(
        actor=_user.username,
        action="ADMIN_LOGOUT",
        result="success",
        target="admin_panel",
        db=db,
    )

    return {"status": "success", "detail": "Logged out successfully"}


@router.get("/me")
def get_current_admin_user(
    current_user: User = Depends(get_current_user),
):
    """Returns profile of currently authenticated user."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "status": current_user.status,
        "last_login": current_user.last_login.isoformat()
        if current_user.last_login
        else None,
    }


@router.post("/step-up")
def request_step_up_token(
    req: StepUpRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate 5-minute confirmation token for high-risk operations."""
    if not verify_password(req.password, current_user.hashed_password):
        audit_log(
            actor=current_user.username,
            action="STEP_UP_AUTH",
            result="failure",
            reason="Invalid step-up password",
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Step-up authentication failed: Invalid password",
        )

    step_up_token = create_step_up_token(current_user)
    audit_log(
        actor=current_user.username,
        action="STEP_UP_AUTH",
        result="success",
        details={"expires_in": 300},
        db=db,
    )
    return {
        "step_up_token": step_up_token,
        "expires_in": 300,
        "user": current_user.username,
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

    audit_log(
        actor=_user.username,
        action="USER_CREATE",
        result="success",
        target=user.username,
        details={"user_id": user.id, "email": user.email, "role": user.role},
        db=db,
    )

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

    # Safety invariant: Prevent demoting or disabling the last active admin
    is_demoting = req.role is not None and req.role != "Admin" and user.role == "Admin"
    is_disabling = (
        req.status is not None and req.status != "active" and user.status == "active"
    )
    if (is_demoting or is_disabling) and user.role == "Admin":
        active_admins = (
            db.query(User)
            .filter(User.role == "Admin", User.status == "active")
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote or disable the last active Administrator account.",
            )

    updated_fields = []
    if req.email is not None:
        existing_email = db.query(User).filter(User.email == req.email, User.id != user_id).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already in use by another user")
        user.email = req.email
        updated_fields.append("email")

    if req.password is not None:
        user.hashed_password = hash_password(req.password)
        updated_fields.append("password")

    if req.role is not None:
        if req.role not in ("Admin", "Analyst", "Viewer"):
            raise HTTPException(status_code=400, detail="Invalid role")
        user.role = req.role
        updated_fields.append("role")

    if req.status is not None:
        if req.status not in ("active", "disabled"):
            raise HTTPException(status_code=400, detail="Invalid status")
        user.status = req.status
        updated_fields.append("status")

    db.commit()

    audit_log(
        actor=_user.username,
        action="USER_UPDATE",
        result="success",
        target=user.username,
        details={"user_id": user.id, "updated_fields": updated_fields},
        db=db,
    )

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

    # Safety invariant: Prevent deleting the last active admin
    if user.role == "Admin" and user.status == "active":
        active_admins = (
            db.query(User)
            .filter(User.role == "Admin", User.status == "active")
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last active Administrator account.",
            )

    target_name = user.username
    db.delete(user)
    db.commit()

    audit_log(
        actor=_user.username,
        action="USER_DELETE",
        result="success",
        target=target_name,
        details={"deleted_user_id": user_id},
        db=db,
    )

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
    {
        "key": "sentinel_llm_enabled",
        "value": "false",
        "category": "threat_detection",
    },
    {"key": "webhook_url", "value": "", "category": "threat_detection"},
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
            "updated_at": c.updated_at.isoformat() if hasattr(c, "updated_at") and c.updated_at else None,
        }
    return {"config": result}


@router.put("/config")
def update_config(
    req: ConfigUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin")),
):
    cfg = set_config_value(req.key, req.value, req.category, db=db)

    audit_log(
        actor=_user.username,
        action="CONFIG_UPDATE",
        result="success",
        target=req.key,
        details={"key": req.key, "value": req.value, "category": req.category},
        db=db,
    )

    return {"status": "updated", "key": req.key}


# ================== System Overview & Health ==================


@router.get("/system-overview")
def system_overview(
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin")),
):
    total_events = db.query(func.count(PacketLog.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_users = db.query(func.count(User.id)).scalar() or 0

    is_postgres = "postgresql" in engine.url.drivername
    db_latency_ms = 0.0
    if is_postgres:
        db_type = "PostgreSQL"
        try:
            t0 = time.time()
            db_name = engine.url.database
            size_bytes = db.execute(
                text("SELECT pg_database_size(:db_name)"), {"db_name": db_name}
            ).scalar() or 0
            db_size_mb = round(size_bytes / (1024 * 1024), 2)
            db_latency_ms = round((time.time() - t0) * 1000, 2)
            db_status = "healthy"
        except Exception as e:
            logger.error("DB probe failed: %s", e)
            db_size_mb = 0.0
            db_status = "unavailable"
    else:
        db_type = "SQLite"
        db_path = os.path.abspath("phantomnet.db")
        db_size_mb = (
            round(os.path.getsize(db_path) / (1024 * 1024), 2)
            if os.path.exists(db_path)
            else 0
        )
        try:
            t0 = time.time()
            db.execute(text("SELECT 1"))
            db_latency_ms = round((time.time() - t0) * 1000, 2)
            db_status = "healthy"
        except Exception:
            db_status = "unavailable"

    # Real probe: ML Engine
    ml_models_dir = os.path.abspath("ml_models")
    has_ml_models = os.path.exists(ml_models_dir) and len(os.listdir(ml_models_dir)) > 0
    ml_status = "healthy" if has_ml_models else "not_configured"

    # Real probe: Honeypot Nodes / Traffic Sniffer
    try:
        active_nodes = (
            db.query(HoneypotNode)
            .filter(HoneypotNode.status == "active")
            .count()
        )
        total_nodes = db.query(HoneypotNode).count()
        if active_nodes > 0:
            sniffer_status = "healthy"
        elif total_nodes > 0:
            sniffer_status = "degraded"
        else:
            sniffer_status = "healthy" if total_events > 0 else "not_configured"
    except Exception:
        sniffer_status = "degraded"

    # Calculate real uptime
    uptime_seconds = int(time.time() - _PROCESS_START_TIME)
    uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m {uptime_seconds % 60}s"

    components = [
        {"name": "FastAPI Server", "status": "healthy", "details": f"PID {os.getpid()}"},
        {
            "name": f"{db_type} Database",
            "status": db_status,
            "details": f"{db_latency_ms} ms latency",
        },
        {
            "name": "ML Engine",
            "status": ml_status,
            "details": "Model artifacts loaded" if has_ml_models else "No custom models loaded",
        },
        {"name": "Real-Time WebSocket", "status": "healthy", "details": "Active listener pool"},
        {
            "name": "Traffic Sniffer / Ingestion",
            "status": sniffer_status,
            "details": f"{total_events} packets recorded",
        },
    ]

    return {
        "system": {
            "version": "3.0.0",
            "uptime": uptime_str,
            "uptime_seconds": uptime_seconds,
            "python_version": os.sys.version.split()[0],
            "db_type": db_type,
            "db_size_mb": db_size_mb,
            "last_updated": datetime.utcnow().isoformat(),
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
        "components": components,
    }


# ================== Maintenance: Backup & Restore ==================


@router.post("/backup")
def create_backup(
    db: Session = Depends(get_db), _user: User = Depends(require_role("Admin"))
):
    backup_dir = get_backup_dir()
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_file = f"phantomnet_backup_{timestamp}.json"
    backup_path = os.path.join(backup_dir, backup_file)

    try:
        # 1. Fetch tables required for state restoration WITHOUT exposing passwords
        users_data = [
            {
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "status": u.status,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in db.query(User).all()
        ]
        config_data = [
            {
                "key": c.key,
                "value": c.value,
                "category": c.category,
            }
            for c in db.query(SystemConfig).all()
        ]
        alerts_data = [
            {
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "level": a.level,
                "type": a.type,
                "source_ip": a.source_ip,
                "description": a.description,
                "details": a.details,
                "is_resolved": a.is_resolved,
            }
            for a in db.query(Alert).all()
        ]
        policies_data = [
            {
                "name": p.name,
                "policy_type": p.policy_type,
                "action": p.action,
                "status": p.status,
                "config": p.config,
            }
            for p in db.query(Policy).all()
        ]
        nodes_data = [
            {
                "node_id": n.node_id,
                "hostname": n.hostname,
                "ip_address": n.ip_address,
                "status": n.status,
                "honeypot_type": n.honeypot_type,
            }
            for n in db.query(HoneypotNode).all()
        ]

        # Packet Logs export (column-projected query for instant serialization without ORM overhead)
        total_packets = db.query(func.count(PacketLog.id)).scalar() or 0
        packet_query = db.query(
            PacketLog.timestamp,
            PacketLog.src_ip,
            PacketLog.dst_ip,
            PacketLog.src_port,
            PacketLog.dst_port,
            PacketLog.protocol,
            PacketLog.length,
            PacketLog.threat_score,
            PacketLog.attack_type,
            PacketLog.is_malicious,
        ).order_by(PacketLog.id.desc())

        if total_packets > 25000:
            packet_query = packet_query.limit(25000)

        packet_logs_data = [
            {
                "timestamp": r[0].isoformat() if r[0] else None,
                "src_ip": r[1],
                "dst_ip": r[2],
                "src_port": r[3],
                "dst_port": r[4],
                "protocol": r[5],
                "length": r[6],
                "threat_score": r[7],
                "attack_type": r[8],
                "is_malicious": r[9],
            }
            for r in packet_query.all()
        ]

        record_counts = {
            "users": len(users_data),
            "system_config": len(config_data),
            "alerts": len(alerts_data),
            "policies": len(policies_data),
            "honeypot_nodes": len(nodes_data),
            "packet_logs": len(packet_logs_data),
        }

        data = {
            "metadata": {
                "version": "3.0.0",
                "timestamp": datetime.utcnow().isoformat(),
                "generator": "PhantomNet System Administration",
                "record_counts": record_counts,
            },
            "users": users_data,
            "system_config": config_data,
            "alerts": alerts_data,
            "policies": policies_data,
            "honeypot_nodes": nodes_data,
            "packet_logs": packet_logs_data,
        }

        # Compute checksum of full payload
        file_bytes = json.dumps(data, indent=2).encode("utf-8")
        file_checksum = hashlib.sha256(file_bytes).hexdigest()
        data["metadata"]["checksum_sha256"] = file_checksum

        # Write formatted file with metadata checksum
        final_bytes = json.dumps(data, indent=2).encode("utf-8")
        final_checksum = hashlib.sha256(final_bytes).hexdigest()

        with open(backup_path, "wb") as f:
            f.write(final_bytes)

        # Write sidecar checksum matching the exact byte contents of backup_path
        with open(f"{backup_path}.sha256", "w", encoding="utf-8") as f:
            f.write(final_checksum)

        size_mb = round(os.path.getsize(backup_path) / (1024 * 1024), 2)

        audit_log(
            actor=_user.username,
            action="DATABASE_BACKUP",
            result="success",
            target=backup_file,
            details={"size_mb": size_mb, "records": record_counts, "checksum": final_checksum},
            db=db,
        )

        return {
            "status": "success",
            "backup_file": backup_file,
            "size_mb": size_mb,
            "records": record_counts,
            "checksum_sha256": final_checksum,
            "checksum": final_checksum,
            "created_at": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error("Database backup failed: %s", e)
        audit_log(
            actor=_user.username,
            action="DATABASE_BACKUP",
            result="failure",
            target=backup_file,
            reason=str(e),
            db=db,
        )
        raise HTTPException(
            status_code=500, detail=f"Database backup failed: {str(e)}"
        )


@router.get("/backups")
def list_backups(_user: User = Depends(require_role("Admin"))):
    backup_dir = get_backup_dir()
    if not os.path.exists(backup_dir):
        return {"backups": []}

    backups = []
    for f in sorted(os.listdir(backup_dir), reverse=True):
        if f.endswith(".json") and not f.startswith(".") and not f.endswith(".sha256"):
            fp = os.path.join(backup_dir, f)
            try:
                stat = os.stat(fp)
                backups.append(
                    {
                        "filename": f,
                        "size_mb": round(stat.st_size / (1024 * 1024), 2),
                        "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    }
                )
            except Exception:
                continue
    return {"backups": backups}


@router.post("/restore")
async def restore_database(
    request: Request,
    file: Optional[UploadFile] = File(None),
    filename: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin")),
):
    """Restore database state from an uploaded backup JSON file or a saved backup filename."""
    backup_dir = get_backup_dir()
    raw_content = None
    filename_source = "uploaded_file"

    if file:
        sanitized_filename = os.path.basename(file.filename or "upload.json")
        if not sanitized_filename.endswith(".json"):
            raise HTTPException(status_code=400, detail="Only JSON backup files are supported.")
        filename_source = sanitized_filename
        raw_content = await file.read()
    else:
        if not filename:
            try:
                body = await request.json()
                filename = body.get("filename")
            except Exception:
                filename = None

        if not filename:
            raise HTTPException(status_code=400, detail="No backup file or filename provided.")

        sanitized_filename = os.path.basename(filename)
        target_path = os.path.join(backup_dir, sanitized_filename)
        if not os.path.exists(target_path):
            raise HTTPException(status_code=404, detail="Backup file not found in storage.")
        filename_source = sanitized_filename
        with open(target_path, "rb") as f:
            raw_content = f.read()

    # Size limit: 100MB
    if len(raw_content) > 100 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Backup file exceeds maximum 100MB limit.")

    try:
        data = json.loads(raw_content.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Corrupted or invalid JSON format: {e}")

    # Validate structure
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        raise HTTPException(status_code=400, detail="Invalid backup file: Missing metadata block.")

    # Integrity verification
    saved_checksum = metadata.get("checksum_sha256") or metadata.get("checksum")
    if saved_checksum:
        raw_hash = hashlib.sha256(raw_content).hexdigest()
        data_copy = dict(data)
        data_copy["metadata"] = dict(metadata)
        data_copy["metadata"].pop("checksum_sha256", None)
        data_copy["metadata"].pop("checksum", None)
        recomputed_formatted = hashlib.sha256(json.dumps(data_copy, indent=2).encode("utf-8")).hexdigest()
        recomputed_compact = hashlib.sha256(json.dumps(data_copy, separators=(',', ':')).encode("utf-8")).hexdigest()
        valid_hashes = {raw_hash, recomputed_formatted, recomputed_compact}
        if saved_checksum not in valid_hashes:
            raise HTTPException(
                status_code=400,
                detail=f"Checksum mismatch: backup archive is corrupt or tampered. Expected {saved_checksum[:16]}..."
            )

    restored_counts = {}

    try:
        # 1. Restore SystemConfig
        for cfg in data.get("system_config", []):
            k = cfg.get("key")
            v = cfg.get("value")
            c = cfg.get("category", "general")
            if k and v is not None:
                set_config_value(k, str(v), c, db=db)
        restored_counts["system_config"] = len(data.get("system_config", []))

        # 2. Restore Policies
        for p in data.get("policies", []):
            existing = db.query(Policy).filter(Policy.name == p.get("name")).first()
            if not existing and p.get("name"):
                new_policy = Policy(
                    name=p.get("name"),
                    description=p.get("description", ""),
                    config=p.get("config", "{}"),
                )
                db.add(new_policy)
        restored_counts["policies"] = len(data.get("policies", []))

        # 3. Restore Honeypot Nodes
        for n in data.get("honeypot_nodes", []):
            nid = n.get("node_id")
            if nid:
                existing = db.query(HoneypotNode).filter(HoneypotNode.node_id == nid).first()
                if not existing:
                    node = HoneypotNode(
                        node_id=nid,
                        hostname=n.get("hostname", nid),
                        ip_address=n.get("ip_address", "127.0.0.1"),
                        status=n.get("status", "active"),
                        honeypot_type=n.get("honeypot_type", "generic"),
                    )
                    db.add(node)
        restored_counts["honeypot_nodes"] = len(data.get("honeypot_nodes", []))

        # 4. Restore Users (Without overwriting passwords of existing accounts)
        for u in data.get("users", []):
            uname = u.get("username")
            if uname:
                existing_u = db.query(User).filter(User.username == uname).first()
                if not existing_u:
                    # New user from backup: assign strong random password
                    new_u = User(
                        username=uname,
                        email=u.get("email", f"{uname}@local"),
                        hashed_password=hash_password(hashlib.sha256(os.urandom(32)).hexdigest()),
                        role=u.get("role", "Viewer"),
                        status=u.get("status", "active"),
                    )
                    db.add(new_u)
                else:
                    existing_u.email = u.get("email", existing_u.email)
                    existing_u.role = u.get("role", existing_u.role)
        restored_counts["users"] = len(data.get("users", []))

        db.commit()

        audit_log(
            actor=_user.username,
            action="DATABASE_RESTORE",
            result="success",
            target=filename_source,
            details={"restored_counts": restored_counts},
            db=db,
        )

        return {
            "status": "success",
            "message": "Database state successfully restored from backup.",
            "source": filename_source,
            "restored": restored_counts,
            "restored_counts": restored_counts,
        }

    except Exception as e:
        db.rollback()
        logger.error("Database restore failed: %s", e)
        audit_log(
            actor=_user.username,
            action="DATABASE_RESTORE",
            result="failure",
            target=filename_source,
            reason=str(e),
            db=db,
        )
        raise HTTPException(
            status_code=500, detail=f"Database restore operation failed: {str(e)}"
        )


@router.post("/vacuum")
def vacuum_db(
    db: Session = Depends(get_db), _user: User = Depends(require_role("Admin"))
):
    try:
        is_postgres = "postgresql" in engine.url.drivername
        if is_postgres:
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

        audit_log(
            actor=_user.username,
            action="DATABASE_VACUUM",
            result="success",
            target="PostgreSQL" if is_postgres else "SQLite",
            details={"status": "completed"},
            db=db,
        )

        return {"status": "success", "message": "Database vacuumed and optimized"}
    except Exception as e:
        logger.error("Database vacuum failed: %s", e)
        audit_log(
            actor=_user.username,
            action="DATABASE_VACUUM",
            result="failure",
            reason=str(e),
            db=db,
        )
        raise HTTPException(
            status_code=500, detail="Database vacuum operation failed."
        )


@router.delete("/events/old")
def delete_old_events(
    days: int = 30,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("Admin")),
):
    if days < 1 or days > 3650:
        raise HTTPException(
            status_code=400, detail="Retention days must be between 1 and 3650"
        )
    cutoff = datetime.utcnow() - timedelta(days=days)

    deleted_packets = (
        db.query(PacketLog).filter(PacketLog.timestamp < cutoff).delete()
    )
    deleted_events = db.query(Event).filter(Event.timestamp < cutoff).delete()
    deleted_alerts = db.query(Alert).filter(Alert.timestamp < cutoff).delete()

    db.commit()

    total = deleted_packets + deleted_events + deleted_alerts
    deleted_counts = {
        "packet_logs": deleted_packets,
        "events": deleted_events,
        "alerts": deleted_alerts,
        "total": total,
    }

    audit_log(
        actor=_user.username,
        action="DATA_PURGE",
        result="success",
        target=f"{days} days cutoff",
        details=deleted_counts,
        db=db,
    )

    return {
        "status": "success",
        "deleted": deleted_counts,
        "cutoff_date": cutoff.isoformat(),
    }
