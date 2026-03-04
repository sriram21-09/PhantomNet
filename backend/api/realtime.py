from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import json
import logging
import asyncio

logger = logging.getLogger("realtime_ws")

class RealTimeManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self.lock:
            self.active_connections.append(websocket)
        logger.info(f"New real-time client connected. Total: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self.lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"Real-time client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message_type: str, payload: Any):
        if not self.active_connections:
            return

        message = json.dumps({
            "type": message_type,
            "payload": payload,
            "timestamp": asyncio.get_event_loop().time()
        })

        disconnected = []
        async with self.lock:
            for connection in self.active_connections:
                try:
                    await connection.send_text(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to client: {e}")
                    disconnected.append(connection)
            
            for conn in disconnected:
                if conn in self.active_connections:
                    self.active_connections.remove(conn)

realtime_manager = RealTimeManager()
router = APIRouter(prefix="/api/v1/realtime", tags=["RealTime"])

@router.websocket("/ws")
async def realtime_ws_endpoint(websocket: WebSocket):
    await realtime_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and listen for any client messages
            data = await websocket.receive_text()
            # Echo or handle specific client commands if needed
    except WebSocketDisconnect:
        await realtime_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Real-time WS unexpected error: {e}")
        await realtime_manager.disconnect(websocket)

# Helper function for other services to push data
async def push_realtime_event(event_type: str, data: Any):
    await realtime_manager.broadcast(event_type, data)
