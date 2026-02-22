"""
coordinator.py — Distributed Honeypot Mesh Coordinator
Week9-Day1 | PhantomNet Project

A FastAPI microservice that acts as the central coordination hub for the
honeypot mesh. Honeypot nodes register themselves, send heartbeats, report
events/alerts, and receive shared threat intelligence.

Run standalone:
    uvicorn backend.services.coordinator:app --host 0.0.0.0 --port 8001 --reload
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("coordinator")

# ---------------------------------------------------------------------------
# JSON Message Schemas (Pydantic Models)
# ---------------------------------------------------------------------------

class RegisterMessage(BaseModel):
    """Sent by a honeypot node on startup to join the mesh."""
    node_id: str = Field(..., description="Unique identifier for this honeypot node")
    host: str = Field(..., description="Host/IP address of the honeypot")
    port: int = Field(..., ge=1, le=65535, description="Port the honeypot listens on")
    protocol: str = Field(..., description="Protocol type: SSH, HTTP, FTP, SMTP, etc.")
    version: str = Field(default="1.0.0", description="Honeypot client version")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Extra node-specific info")


class HeartbeatMessage(BaseModel):
    """Sent periodically from a node to signal it is still alive."""
    node_id: str = Field(..., description="Unique identifier for this honeypot node")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time of this heartbeat"
    )
    status: str = Field(default="active", description="Node status: active | degraded | stopping")
    event_count: int = Field(default=0, ge=0, description="Total events captured since startup")
    cpu_percent: Optional[float] = Field(default=None, description="Optional CPU usage metric")
    memory_mb: Optional[float] = Field(default=None, description="Optional memory usage in MB")


class EventMessage(BaseModel):
    """A capture event reported by a honeypot (any interaction with the decoy)."""
    node_id: str = Field(..., description="Reporting honeypot node ID")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the event occurred"
    )
    src_ip: str = Field(..., description="Source IP address of the attacker/scanner")
    src_port: Optional[int] = Field(default=None, description="Source port (if known)")
    dst_port: Optional[int] = Field(default=None, description="Destination port on the honeypot")
    protocol: str = Field(..., description="Protocol triggered (SSH, HTTP, FTP, SMTP)")
    event_type: str = Field(default="connection", description="Type: connection | login_attempt | command | scan")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Protocol-specific event payload")


class AlertMessage(BaseModel):
    """A high-severity alert that should be broadcast to all other nodes."""
    node_id: str = Field(..., description="Reporting honeypot node ID")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the alert was raised"
    )
    severity: str = Field(default="HIGH", description="Severity level: LOW | MEDIUM | HIGH | CRITICAL")
    src_ip: str = Field(..., description="Attacker IP address triggering the alert")
    description: str = Field(..., description="Human-readable alert description")
    alert_type: str = Field(default="brute_force", description="Type: brute_force | scan | exploit | anomaly")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional evidence/context")


class DeregisterMessage(BaseModel):
    """Sent by a node when it is shutting down gracefully."""
    node_id: str = Field(..., description="Node that is leaving the mesh")
    reason: Optional[str] = Field(default="graceful_shutdown", description="Reason for deregistration")


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class NodeInfo(BaseModel):
    node_id: str
    host: str
    port: int
    protocol: str
    version: str
    registered_at: datetime
    last_heartbeat: Optional[datetime]
    status: str
    event_count: int
    metadata: Optional[Dict[str, Any]]


class ThreatIntelResponse(BaseModel):
    blocked_ips: List[str]
    high_severity_ips: List[str]
    recent_alerts: List[Dict[str, Any]]
    total_events: int
    last_updated: datetime


# ---------------------------------------------------------------------------
# In-Memory State
# ---------------------------------------------------------------------------

class CoordinatorState:
    """Central in-memory state store for the coordinator."""

    def __init__(self) -> None:
        # node_id -> node info dict
        self.nodes: Dict[str, Dict[str, Any]] = {}
        # list of all EventMessage dicts
        self.events: List[Dict[str, Any]] = []
        # list of all AlertMessage dicts
        self.alerts: List[Dict[str, Any]] = []
        # IP -> list of alerts it triggered
        self.threat_intel: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # node_id -> list of heartbeat timestamps (for health tracking)
        self.heartbeats: Dict[str, List[datetime]] = defaultdict(list)
        # IPs that appear in HIGH/CRITICAL alerts → auto-blocked
        self.blocked_ips: set = set()

    def register_node(self, msg: RegisterMessage) -> Dict[str, Any]:
        self.nodes[msg.node_id] = {
            "node_id": msg.node_id,
            "host": msg.host,
            "port": msg.port,
            "protocol": msg.protocol,
            "version": msg.version,
            "metadata": msg.metadata,
            "registered_at": datetime.now(timezone.utc),
            "last_heartbeat": None,
            "status": "active",
            "event_count": 0,
        }
        logger.info("Node registered: %s (%s on %s:%d)", msg.node_id, msg.protocol, msg.host, msg.port)
        return self.nodes[msg.node_id]

    def update_heartbeat(self, msg: HeartbeatMessage) -> Dict[str, Any]:
        if msg.node_id not in self.nodes:
            raise KeyError(f"Unknown node: {msg.node_id}")
        node = self.nodes[msg.node_id]
        node["last_heartbeat"] = msg.timestamp
        node["status"] = msg.status
        node["event_count"] = msg.event_count
        self.heartbeats[msg.node_id].append(msg.timestamp)
        logger.debug("Heartbeat from %s | status=%s | events=%d", msg.node_id, msg.status, msg.event_count)
        return node

    def record_event(self, msg: EventMessage) -> Dict[str, Any]:
        event = msg.model_dump()
        event["received_at"] = datetime.now(timezone.utc)
        self.events.append(event)
        # Update per-node event count
        if msg.node_id in self.nodes:
            self.nodes[msg.node_id]["event_count"] += 1
        self.threat_intel[msg.src_ip].append({"type": "event", "data": event})
        logger.debug("Event: %s -> %s [%s]", msg.src_ip, msg.node_id, msg.event_type)
        return event

    def record_alert(self, msg: AlertMessage) -> Dict[str, Any]:
        alert = msg.model_dump()
        alert["received_at"] = datetime.now(timezone.utc)
        self.alerts.append(alert)
        self.threat_intel[msg.src_ip].append({"type": "alert", "data": alert})
        # Auto-block HIGH and CRITICAL IPs
        if msg.severity in ("HIGH", "CRITICAL"):
            self.blocked_ips.add(msg.src_ip)
        logger.warning("Alert [%s] from %s: %s | src_ip=%s", msg.severity, msg.node_id, msg.description, msg.src_ip)
        return alert

    def deregister_node(self, msg: DeregisterMessage) -> bool:
        if msg.node_id in self.nodes:
            del self.nodes[msg.node_id]
            self.heartbeats.pop(msg.node_id, None)
            logger.info("Node deregistered: %s (reason: %s)", msg.node_id, msg.reason)
            return True
        return False

    def get_active_nodes(self) -> List[Dict[str, Any]]:
        """Return nodes that sent a heartbeat in the last 2 minutes or were never heartbeat-checked."""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=2)
        active = []
        for node in self.nodes.values():
            hb = node.get("last_heartbeat")
            if hb is None or (hb.tzinfo is None and hb > cutoff.replace(tzinfo=None)) or (hb.tzinfo is not None and hb > cutoff):
                active.append(node)
        return active

    def build_threat_intel(self) -> Dict[str, Any]:
        recent_alerts = [
            {k: (str(v) if isinstance(v, datetime) else v) for k, v in a.items()}
            for a in self.alerts[-50:]  # last 50 alerts
        ]
        high_severity_ips = list({
            a["src_ip"] for a in self.alerts
            if a.get("severity") in ("HIGH", "CRITICAL")
        })
        return {
            "blocked_ips": list(self.blocked_ips),
            "high_severity_ips": high_severity_ips,
            "recent_alerts": recent_alerts,
            "total_events": len(self.events),
            "last_updated": datetime.now(timezone.utc),
        }


# Module-level singleton
state = CoordinatorState()

# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="PhantomNet Honeypot Coordinator",
    description=(
        "Central coordination hub for the PhantomNet honeypot mesh. "
        "Honeypot nodes register, send heartbeats, report events/alerts, "
        "and receive shared threat intelligence."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["health"])
async def root() -> Dict[str, Any]:
    """Health check — returns coordinator status summary."""
    return {
        "service": "PhantomNet Coordinator",
        "status": "running",
        "version": "1.0.0",
        "registered_nodes": len(state.nodes),
        "total_events": len(state.events),
        "total_alerts": len(state.alerts),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/register", status_code=status.HTTP_201_CREATED, tags=["mesh"])
async def register_node(msg: RegisterMessage) -> Dict[str, Any]:
    """
    Register a new honeypot node with the coordinator.
    Should be called by each honeypot on startup.
    """
    if msg.node_id in state.nodes:
        # Re-registration: update the node info
        logger.info("Re-registration of existing node: %s", msg.node_id)
        state.nodes[msg.node_id].update({
            "host": msg.host,
            "port": msg.port,
            "protocol": msg.protocol,
            "version": msg.version,
            "metadata": msg.metadata,
            "status": "active",
            "registered_at": datetime.now(timezone.utc),
        })
        node = state.nodes[msg.node_id]
    else:
        node = state.register_node(msg)

    return {
        "success": True,
        "message": f"Node '{msg.node_id}' registered successfully",
        "node": node,
        "active_peers": len(state.nodes) - 1,
        "coordinator_time": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/heartbeat", tags=["mesh"])
async def heartbeat(msg: HeartbeatMessage) -> Dict[str, Any]:
    """
    Receive a periodic heartbeat from a registered honeypot node.
    Nodes should call this every 30 seconds to maintain active status.
    """
    try:
        node = state.update_heartbeat(msg)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return {
        "success": True,
        "message": "Heartbeat acknowledged",
        "node_id": msg.node_id,
        "coordinator_time": datetime.now(timezone.utc).isoformat(),
        "active_nodes": len(state.get_active_nodes()),
    }


@app.post("/event", status_code=status.HTTP_201_CREATED, tags=["intelligence"])
async def report_event(msg: EventMessage) -> Dict[str, Any]:
    """
    Report a capture event from a honeypot node.
    Called whenever the honeypot records a new interaction.
    """
    if msg.node_id not in state.nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node '{msg.node_id}' is not registered. Please register first.",
        )
    event = state.record_event(msg)
    return {
        "success": True,
        "message": "Event recorded",
        "event_id": len(state.events),
        "total_events": len(state.events),
        "src_ip_seen_count": len(state.threat_intel.get(msg.src_ip, [])),
    }


@app.post("/alert", status_code=status.HTTP_201_CREATED, tags=["intelligence"])
async def report_alert(msg: AlertMessage) -> Dict[str, Any]:
    """
    Report a high-severity alert. HIGH and CRITICAL alerts automatically add
    the source IP to the shared blocklist broadcast to all nodes.
    """
    if msg.node_id not in state.nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node '{msg.node_id}' is not registered. Please register first.",
        )
    alert = state.record_alert(msg)
    return {
        "success": True,
        "message": "Alert recorded and broadcast to mesh",
        "alert_id": len(state.alerts),
        "ip_blocked": msg.src_ip in state.blocked_ips,
        "severity": msg.severity,
        "total_alerts": len(state.alerts),
    }


@app.get("/nodes", tags=["mesh"])
async def list_nodes(active_only: bool = False) -> Dict[str, Any]:
    """
    List all registered honeypot nodes.
    Set `active_only=true` to filter for nodes with recent heartbeats.
    """
    nodes = state.get_active_nodes() if active_only else list(state.nodes.values())
    # Serialise datetimes to ISO strings
    serialised = [
        {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in n.items()}
        for n in nodes
    ]
    return {
        "total": len(serialised),
        "nodes": serialised,
    }


@app.get("/threats", tags=["intelligence"])
async def get_threats() -> Dict[str, Any]:
    """
    Return the current shared threat intelligence snapshot.
    Includes blocklist, high-severity IPs, and recent alerts.
    Honeypot nodes should poll this to stay in sync.
    """
    intel = state.build_threat_intel()
    intel["last_updated"] = intel["last_updated"].isoformat()
    return intel


@app.post("/deregister", tags=["mesh"])
async def deregister_node(msg: DeregisterMessage) -> Dict[str, Any]:
    """
    Gracefully remove a honeypot node from the mesh.
    Should be called by the node on shutdown.
    """
    removed = state.deregister_node(msg)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node '{msg.node_id}' was not registered.",
        )
    return {
        "success": True,
        "message": f"Node '{msg.node_id}' deregistered",
        "remaining_nodes": len(state.nodes),
    }


@app.get("/stats", tags=["health"])
async def get_stats() -> Dict[str, Any]:
    """Return coordinator-level aggregate statistics."""
    protocol_counts: Dict[str, int] = defaultdict(int)
    for node in state.nodes.values():
        protocol_counts[node["protocol"]] += 1

    severity_counts: Dict[str, int] = defaultdict(int)
    for alert in state.alerts:
        severity_counts[alert.get("severity", "UNKNOWN")] += 1

    return {
        "registered_nodes": len(state.nodes),
        "active_nodes": len(state.get_active_nodes()),
        "total_events": len(state.events),
        "total_alerts": len(state.alerts),
        "blocked_ips": len(state.blocked_ips),
        "unique_attacker_ips": len(state.threat_intel),
        "protocol_distribution": dict(protocol_counts),
        "alert_severity_distribution": dict(severity_counts),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Entry-point for direct execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("coordinator:app", host="0.0.0.0", port=8001, reload=True)
