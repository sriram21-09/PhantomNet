import os
import sys
import socket
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from database.database import get_db, SessionLocal
from database.models import PacketLog, HoneypotNode

from middleware.auth import get_current_user

router = APIRouter(
    prefix="/api/honeypots",
    tags=["Honeypots"],
    dependencies=[Depends(get_current_user)],
)

# Authoritative default honeypot definitions reflecting the Docker deployment topology
DEFAULT_HONEYPOTS = [
    {
        "node_id": "hp-ssh-01",
        "name": "SSH",
        "protocol": "SSH",
        "hostname": "ssh_honeypot",
        "ip_address": "127.0.0.1",
        "honeypot_type": "SSH",
        "internal_port": 2222,
        "external_port": 2722,
        "description": "High-interaction SSH terminal with session recording and brute-force detection.",
    },
    {
        "node_id": "hp-http-01",
        "name": "HTTP",
        "protocol": "HTTP",
        "hostname": "http_honeypot",
        "ip_address": "127.0.0.1",
        "honeypot_type": "HTTP",
        "internal_port": 8080,
        "external_port": 8080,
        "description": "Deceptive web application trap simulating admin portals and credential endpoints.",
    },
    {
        "node_id": "hp-ftp-01",
        "name": "FTP",
        "protocol": "FTP",
        "hostname": "ftp_honeypot",
        "ip_address": "127.0.0.1",
        "honeypot_type": "FTP",
        "internal_port": 2121,
        "external_port": 2721,
        "description": "Virtual FTP file server capturing unauthorized directory traversals and transfers.",
    },
    {
        "node_id": "hp-smtp-01",
        "name": "SMTP",
        "protocol": "SMTP",
        "hostname": "smtp-honeypot",
        "ip_address": "127.0.0.1",
        "honeypot_type": "SMTP",
        "internal_port": 2525,
        "external_port": 2725,
        "description": "Mail transfer honeypot identifying spam relay probes and email harvest botnets.",
    },
]

CONFIG_MAP = {cfg["honeypot_type"].upper(): cfg for cfg in DEFAULT_HONEYPOTS}


class HoneypotResponse(BaseModel):
    id: Optional[str] = None
    node_id: Optional[str] = None
    name: str
    protocol: str
    status: str
    internal_port: int
    external_port: int
    port: int  # Backwards compatibility: exposes internal_port
    host: Optional[str] = None
    last_seen: Optional[str] = None
    packet_count: int
    total_events: int  # Backwards compatibility: equals packet_count
    description: Optional[str] = None


def seed_default_honeypot_nodes(db: Session) -> List[HoneypotNode]:
    """
    Seeds default honeypot nodes into the honeypot_nodes table if empty or missing,
    ensuring honeypot_nodes is the authoritative persistence model.
    """
    for cfg in DEFAULT_HONEYPOTS:
        existing = (
            db.query(HoneypotNode)
            .filter(
                (HoneypotNode.node_id == cfg["node_id"])
                | (HoneypotNode.honeypot_type == cfg["honeypot_type"])
            )
            .first()
        )
        if not existing:
            node = HoneypotNode(
                node_id=cfg["node_id"],
                hostname=cfg["hostname"],
                ip_address=cfg["ip_address"],
                honeypot_type=cfg["honeypot_type"],
                status="active",
                last_seen=datetime.utcnow(),
            )
            db.add(node)
    try:
        db.commit()
    except Exception:
        db.rollback()

    return db.query(HoneypotNode).order_by(HoneypotNode.id.asc()).all()


def check_port_status(
    host: str,
    internal_port: int,
    external_port: Optional[int] = None,
    fallback_host: str = "127.0.0.1",
    timeout: float = 0.2,
) -> str:
    """
    Checks if a honeypot port is reachable. Returns 'active' or 'inactive'.
    Tries container host on internal port first (standard in Docker network),
    then tries fallback host on internal and external ports.
    """
    candidates = []
    if host and (os.path.exists("/.dockerenv") or "." in host or "_" in host or "-" in host):
        candidates.append((host, internal_port))
    
    if fallback_host:
        candidates.append((fallback_host, internal_port))
        if external_port and external_port != internal_port:
            candidates.append((fallback_host, external_port))

    for target_host, target_port in candidates:
        try:
            with socket.create_connection((target_host, target_port), timeout=timeout):
                return "active"
        except Exception:
            continue

    return "inactive"


@router.get("", response_model=List[HoneypotResponse])
def get_honeypot_status(db: Session = Depends(get_db)):
    """
    Dynamically gets current honeypot container statuses and event counts,
    authoritatively backed by the HoneypotNode persistence table.
    """
    local_session = False
    if not isinstance(db, Session):
        db = SessionLocal()
        local_session = True

    try:
        nodes = db.query(HoneypotNode).order_by(HoneypotNode.id.asc()).all()
        if not nodes:
            nodes = seed_default_honeypot_nodes(db)

        results = []
        for node in nodes:
            proto = (node.honeypot_type or "SSH").upper()
            cfg = CONFIG_MAP.get(proto, {
                "name": proto,
                "protocol": proto,
                "hostname": node.hostname or "127.0.0.1",
                "internal_port": 0,
                "external_port": 0,
                "description": "Deception honeypot node.",
            })

            internal_port = cfg.get("internal_port", 0)
            external_port = cfg.get("external_port", internal_port)
            host = cfg.get("hostname", node.hostname or "127.0.0.1")

            # 1. Check Port Status
            status = check_port_status(host, internal_port, external_port=external_port)

            # 2. Get captured log counts
            count = db.query(PacketLog).filter(PacketLog.protocol == proto).count()

            # 3. Get last active timestamp
            last_log = (
                db.query(PacketLog)
                .filter(PacketLog.protocol == proto)
                .order_by(PacketLog.timestamp.desc())
                .first()
            )

            last_seen = None
            if last_log and last_log.timestamp:
                dt = last_log.timestamp.replace(tzinfo=timezone.utc)
                last_seen = dt.isoformat()
            elif node.last_seen:
                dt = node.last_seen.replace(tzinfo=timezone.utc)
                last_seen = dt.isoformat()

            # Update HoneypotNode record status and last_seen
            try:
                node.status = status
                if last_log and last_log.timestamp:
                    node.last_seen = last_log.timestamp
                db.commit()
            except Exception:
                db.rollback()

            results.append(
                HoneypotResponse(
                    id=str(node.id),
                    node_id=node.node_id or f"hp-{proto.lower()}",
                    name=cfg.get("name", proto),
                    protocol=proto,
                    status=status,
                    internal_port=internal_port,
                    external_port=external_port,
                    port=internal_port,
                    host=host,
                    last_seen=last_seen,
                    packet_count=count,
                    total_events=count,
                    description=cfg.get("description", "Active deception environment."),
                )
            )

        return results
    finally:
        if local_session:
            db.close()


@router.get("/status", response_model=List[HoneypotResponse])
def get_honeypot_status_alias(db: Session = Depends(get_db)):
    """
    Alias route for /api/honeypots/status to support all frontend components.
    """
    return get_honeypot_status(db)

