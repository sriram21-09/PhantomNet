from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import asyncio
import json
import logging

logger = logging.getLogger("topology_ws")
router = APIRouter(prefix="/api/v1/topology", tags=["Topology"])


class TopologyManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"New topology client connected. Total: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(
            f"Topology client disconnected. Total: {len(self.active_connections)}"
        )

    async def broadcast(self, data: Dict[str, Any]):
        message = json.dumps(data)
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")


topology_manager = TopologyManager()


@router.websocket("/ws")
async def topology_ws_endpoint(websocket: WebSocket):
    await topology_manager.connect(websocket)
    try:
        # Initial State Push: Dynamic Node Discovery
        from api.honeypots import get_honeypot_status

        honeypots = get_honeypot_status()

        nodes = [
            {
                "id": "controller",
                "type": "controller",
                "position": {"x": 400, "y": 50},
                "data": {"label": "PHANTOM_OS"},
            }
        ]
        edges = []

        for idx, hp in enumerate(honeypots):
            hp_id = hp["name"].lower().replace(" ", "_")
            nodes.append(
                {
                    "id": hp_id,
                    "type": "honeypot",
                    "position": {"x": 200 + (idx * 200), "y": 250},
                    "data": {"label": hp["name"], "port": hp["port"]},
                }
            )
            edges.append(
                {
                    "id": f"e_ctrl_{hp_id}",
                    "source": "controller",
                    "target": hp_id,
                    "animated": True,
                }
            )

        await websocket.send_text(
            json.dumps({"type": "INIT", "payload": {"nodes": nodes, "edges": edges}})
        )

        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Handle client-to-server messages if needed
    except WebSocketDisconnect:
        topology_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WS unexpected error: {e}")
        topology_manager.disconnect(websocket)


# Service to push updates from other parts of the system
async def push_topology_event(event_type: str, data: Any):
    await topology_manager.broadcast(
        {
            "type": event_type,
            "payload": data,
            "timestamp": asyncio.get_event_loop().time(),
        }
    )
