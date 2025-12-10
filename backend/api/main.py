from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import psycopg2
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="PhantomNet API",
    description="Honeypot threat detection API",
    version="0.1.0"
)

# CORS settings so frontend (React/Vite) can call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db_connection():
    """Create a new DB connection for each request (simple for now)."""
    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "postgres"),
            database=os.getenv("DB_NAME", "phantomnet"),
            port=os.getenv("DB_PORT", "5432"),
        )
        return conn
    except psycopg2.OperationalError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# ---------- Pydantic models ----------

class EventResponse(BaseModel):
    id: int
    timestamp: Optional[str]
    srcip: str
    dstport: int
    username: str
    status: str
    threatscore: float


class StatsResponse(BaseModel):
    total_events: int
    unique_ips: int
    avg_threat: float
    max_threat: float


class ThreatLevelResponse(BaseModel):
    level: str
    color: str


class HealthResponse(BaseModel):
    status: str
    database: str
    timestamp: str


# ---------- Endpoints ----------

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint with DB connectivity."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1;")
        cursor.close()
        conn.close()
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return HealthResponse(
        status="healthy",
        database=db_status,
        timestamp=datetime.utcnow().isoformat()
    )


@app.get("/events", response_model=List[EventResponse])
async def get_events(limit: int = 10, hours: int = 24):
    """Get recent honeypot events."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        since = datetime.utcnow() - timedelta(hours=hours)

        cursor.execute(
            """
            SELECT id, timestamp, srcip, dstport, username, status, threatscore
            FROM events
            WHERE timestamp > %s
            ORDER BY timestamp DESC
            LIMIT %s
            """,
            (since, limit),
        )

        rows = cursor.fetchall()
        events: List[EventResponse] = []

        for row in rows:
            events.append(
                EventResponse(
                    id=row[0],
                    timestamp=row[1].isoformat() if row[1] else None,
                    srcip=row[2],
                    dstport=row[3],
                    username=row[4],
                    status=row[5],
                    threatscore=float(row[6]),
                )
            )

        return events
    finally:
        cursor.close()
        conn.close()


@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get aggregate statistics over all events."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_events,
                COUNT(DISTINCT srcip) AS unique_ips,
                AVG(threatscore) AS avg_threat,
                MAX(threatscore) AS max_threat
            FROM events
            """
        )

        row = cursor.fetchone()

        total_events = row[0] or 0
        unique_ips = row[1] or 0
        avg_threat = float(row[2]) if row[2] is not None else 0.0
        max_threat = float(row[3]) if row[3] is not None else 0.0

        return StatsResponse(
            total_events=total_events,
            unique_ips=unique_ips,
            avg_threat=round(avg_threat, 2),
            max_threat=max_threat,
        )
    finally:
        cursor.close()
        conn.close()


@app.get("/threat-level", response_model=ThreatLevelResponse)
async def get_threat_level():
    """Compute a threat level from average threat score."""
    stats = await get_stats()
    avg = stats.avg_threat

    if avg > 70:
        return ThreatLevelResponse(level="CRITICAL", color="red")
    elif avg > 50:
        return ThreatLevelResponse(level="HIGH", color="orange")
    elif avg > 30:
        return ThreatLevelResponse(level="MEDIUM", color="yellow")
    else:
        return ThreatLevelResponse(level="LOW", color="green")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
