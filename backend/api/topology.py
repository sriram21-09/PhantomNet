import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from database.database import get_db, SessionLocal
from middleware.auth import ws_authenticate, get_current_user
from middleware.security_headers import ALLOWED_ORIGINS

logger = logging.getLogger("topology_ws")
router = APIRouter(prefix="/api/v1/topology", tags=["Topology"])


class TopologyManager:
    """Manages active WebSocket clients for Network Topology visualization.
    
    Supports both direct async broadcast from the main server loop and
    thread-safe broadcast from background worker threads (e.g. ThreatAnalyzer).
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        # Bind active event loop on connection if not already set
        try:
            self.loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        self.active_connections.append(websocket)
        logger.info(
            f"New topology client connected. Total: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                f"Topology client disconnected. Total: {len(self.active_connections)}"
            )

    async def broadcast(self, data: Dict[str, Any]):
        """Asynchronously broadcast data to all connected clients on the current event loop."""
        if not self.active_connections:
            return
        message = json.dumps(data)
        disconnected = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting topology event: {e}")
                disconnected.append(connection)
        for dc in disconnected:
            self.disconnect(dc)

    def broadcast_sync(self, data: Dict[str, Any]):
        """Thread-safe synchronous broadcast dispatchable from background worker threads."""
        if not self.active_connections:
            return
        # If server loop is active and we are not in that loop, schedule thread-safely
        if self.loop and self.loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(self.broadcast(data), self.loop)
                return
            except Exception as e:
                logger.error(f"Failed to schedule threadsafe broadcast: {e}")
        # Fallback if in an active loop
        try:
            current_loop = asyncio.get_running_loop()
            if current_loop and current_loop.is_running():
                current_loop.create_task(self.broadcast(data))
                return
        except RuntimeError:
            pass


topology_manager = TopologyManager()


@router.get("", dependencies=[Depends(get_current_user)])
@router.get("/", dependencies=[Depends(get_current_user)])
def get_topology(db: Session = Depends(get_db)):
    """Fetch logical deception infrastructure topology nodes, edges, and honeypot health."""
    from api.honeypots import get_honeypot_status
    honeypots = get_honeypot_status(db=db)

    nodes = [
        {
            "id": "controller",
            "type": "controller",
            "position": {"x": 400, "y": 50},
            "data": {
                "label": "PHANTOM_OS",
                "sublabel": "CORE CONTROLLER",
                "status": "online",
                "role": "Core Control Plane",
            },
        }
    ]
    edges = []

    for idx, hp in enumerate(honeypots):
        hp_name = hp["name"] if isinstance(hp, dict) else getattr(hp, "name", "Honeypot")
        hp_proto = hp["protocol"] if isinstance(hp, dict) else getattr(hp, "protocol", "SSH")
        hp_internal = hp["internal_port"] if isinstance(hp, dict) else getattr(hp, "internal_port", 0)
        hp_external = hp["external_port"] if isinstance(hp, dict) else getattr(hp, "external_port", hp_internal)
        hp_port = hp["port"] if isinstance(hp, dict) else getattr(hp, "port", hp_internal)
        hp_status = hp["status"] if isinstance(hp, dict) else getattr(hp, "status", "unknown")
        hp_id = str(hp_name).lower().replace(" ", "_")
        nodes.append(
            {
                "id": hp_id,
                "type": "honeypot",
                "position": {"x": 200 + (idx * 200), "y": 250},
                "data": {
                    "label": hp_name,
                    "protocol": hp_proto,
                    "port": hp_external,
                    "internal_port": hp_internal,
                    "external_port": hp_external,
                    "status": hp_status,
                },
            }
        )
        edges.append(
            {
                "id": f"e_ctrl_{hp_id}",
                "source": "controller",
                "target": hp_id,
                "animated": True,
                "data": {"type": "logical_deception_link"},
            }
        )

    return {
        "controller": {
            "name": "PHANTOM_OS",
            "role": "Core Control Plane",
            "status": "online",
        },
        "honeypots": honeypots,
        "nodes": nodes,
        "edges": edges,
    }


@router.websocket("/ws")
async def topology_ws_endpoint(websocket: WebSocket):
    # 1. Validate Origin header to guard against CSWSH
    origin = websocket.headers.get("origin")
    if origin:
        norm_origin = origin.rstrip("/")
        if norm_origin not in ALLOWED_ORIGINS:
            logger.warning("Rejected topology WS from unauthorized origin: %s", origin)
            await websocket.close(code=4003, reason="Forbidden origin")
            return

    # 2. Authenticate session via cookie or Authorization header
    override = websocket.app.dependency_overrides.get(get_db) if hasattr(websocket, "app") else None
    if override:
        db_gen = override()
        db = next(db_gen)
    else:
        db = SessionLocal()

    try:
        user = ws_authenticate(websocket, db)
        if not user:
            logger.warning("Rejected unauthenticated topology WS connection")
            await websocket.close(code=4001, reason="Unauthorized")
            return

        await topology_manager.connect(websocket)
        # Initial State Push: Dynamic Node Discovery
        from api.honeypots import get_honeypot_status
        honeypots = get_honeypot_status(db=db)
    finally:
        db.close()

    try:
        nodes = [
            {
                "id": "controller",
                "type": "controller",
                "position": {"x": 400, "y": 50},
                "data": {
                    "label": "PHANTOM_OS",
                    "sublabel": "CORE CONTROLLER",
                    "status": "online",
                    "role": "Core Control Plane",
                },
            }
        ]
        edges = []

        for idx, hp in enumerate(honeypots):
            hp_name = hp["name"] if isinstance(hp, dict) else getattr(hp, "name", "Honeypot")
            hp_proto = hp["protocol"] if isinstance(hp, dict) else getattr(hp, "protocol", "SSH")
            hp_internal = hp["internal_port"] if isinstance(hp, dict) else getattr(hp, "internal_port", 0)
            hp_external = hp["external_port"] if isinstance(hp, dict) else getattr(hp, "external_port", hp_internal)
            hp_port = hp["port"] if isinstance(hp, dict) else getattr(hp, "port", hp_internal)
            hp_status = hp["status"] if isinstance(hp, dict) else getattr(hp, "status", "unknown")
            hp_id = str(hp_name).lower().replace(" ", "_")
            nodes.append(
                {
                    "id": hp_id,
                    "type": "honeypot",
                    "position": {"x": 200 + (idx * 200), "y": 250},
                    "data": {
                        "label": hp_name,
                        "protocol": hp_proto,
                        "port": hp_external,
                        "internal_port": hp_internal,
                        "external_port": hp_external,
                        "status": hp_status,
                    },
                }
            )
            edges.append(
                {
                    "id": f"e_ctrl_{hp_id}",
                    "source": "controller",
                    "target": hp_id,
                    "animated": True,
                    "data": {"type": "logical_deception_link"},
                }
            )

        await websocket.send_text(
            json.dumps({"type": "INIT", "payload": {"nodes": nodes, "edges": edges}})
        )

        while True:
            # Keep connection alive & handle incoming pings
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") in ["ping", "heartbeat"]:
                    await websocket.send_text(json.dumps({"type": "pong", "timestamp": time.time()}))
            except Exception:
                pass
    except WebSocketDisconnect:
        topology_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WS unexpected error: {e}")
        topology_manager.disconnect(websocket)


async def push_topology_event(event_type: str, data: Any):
    """Async event push for coroutines running on the primary event loop."""
    await topology_manager.broadcast(
        {
            "type": event_type,
            "payload": data,
            "timestamp": time.time(),
        }
    )


def push_topology_event_sync(event_type: str, data: Any):
    """Thread-safe event push for synchronous workers or background threads."""
    topology_manager.broadcast_sync(
        {
            "type": event_type,
            "payload": data,
            "timestamp": time.time(),
        }
    )

