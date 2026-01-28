from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI()

# --- ENABLE CORS (Allow React to talk to Python) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all connections (Safe for local dev)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DATABASE CONFIG (WINDOWS VERSION) ---
DB_CONFIG = {
    "dbname": "phantomnet",
    "user": "phantom",
    "password": "password@321",  # Your password
    "host": "localhost",
    "port": "5432"
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

@app.get("/")
def read_root():
    return {"status": "PhantomNet Intelligence Center is ONLINE 🟢"}

@app.get("/logs")
def get_attack_logs():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 50")
        logs = cur.fetchall()
        conn.close()
        return logs
    except Exception as e:
        print(f"Database Error: {e}")
        return []