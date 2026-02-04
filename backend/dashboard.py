from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
from psycopg2.extras import RealDictCursor
from backend.ml.anomaly_detector import AnomalyDetector
from datetime import datetime, timedelta
import os
import random

# --- IMPORT THE NEW ROUTER ---
from backend.routes.ml_routes import router as ml_routes

app = FastAPI()

# --- REGISTER THE NEW ROUTER ---
# This tells the server: "Send any request starting with /api/ml to the ml_routes file"
app.include_router(ml_routes, prefix="/api/ml", tags=["Machine Learning"])

# --- CORS SETTINGS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DATABASE CONNECTION ---
def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname="phantomnet_db",
            user="postgres",
            password="password",  # Update if you changed your DB password
            host="localhost",
            port="5432"
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# --- EXISTING ENDPOINTS (Do not delete) ---
@app.get("/")
def read_root():
    return {"message": "PhantomNet Backend is Running"}

@app.get("/logs")
def get_logs():
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50")
    logs = cursor.fetchall()
    conn.close()
    return logs

@app.get("/stats")
def get_stats():
    conn = get_db_connection()
    if not conn:
        return {}
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT service_type, COUNT(*) as count FROM logs GROUP BY service_type")
    stats = cursor.fetchall()
    conn.close()
    return stats