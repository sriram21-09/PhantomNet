from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
from psycopg2.extras import RealDictCursor
from backend.ml.anomaly_detector import AnomalyDetector
from datetime import datetime, timedelta
import os
import random

app = FastAPI()

# --- ENABLE CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DATABASE CONFIG ---
DB_CONFIG = {
    "dbname": "phantomnet",
    "user": "phantom",
    "password": "password@321",
    "host": "localhost",
    "port": "5432"
}

# --- LOAD AI MODEL ---
print("🧠 Initializing AI Core...")
detector = AnomalyDetector()
if detector.load():
    print("✅ AI Model Loaded Successfully")
else:
    print("⚠️ No trained model found. Waiting for training...")

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

@app.get("/")
def read_root():
    return {"status": "PhantomNet AI Core is ONLINE 🟢"}

@app.post("/train")
def trigger_training(background_tasks: BackgroundTasks):
    """
    Triggers the AI to learn from the last 1000 logs.
    Runs in the background so it doesn't freeze the dashboard.
    """
    def train_task():
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 1000")
            logs = [dict(row) for row in cur.fetchall()]
            conn.close()
            
            if logs:
                detector.train(logs)
                print("🎓 Training Complete!")
        except Exception as e:
            print(f"Training Failed: {e}")

    background_tasks.add_task(train_task)
    return {"message": "Training started in background..."}

@app.get("/logs")
def get_attack_logs():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 50")
        rows = cur.fetchall()
        conn.close()

        # --- AI ENRICHMENT ---
        enriched_logs = []
        for row in rows:
            log_dict = dict(row)
            
            # Ask the Brain: Is this an anomaly?
            pred, score = detector.predict(log_dict)
            
            # -1 is Anomaly (Red), 1 is Normal (Green)
            log_dict["anomaly_pred"] = int(pred)
            log_dict["anomaly_score"] = float(score)

            enriched_logs.append(log_dict)

        return enriched_logs

    except Exception as e:
        print(f"Database Error: {e}")
        return []

@app.get("/stats")
def get_stats():
    # ... (Same as before)
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT service_type, COUNT(*) as count FROM attack_logs GROUP BY service_type")
        rows = cur.fetchall()
        conn.close()
        return [{"name": row["service_type"], "value": row["count"]} for row in rows]
    except Exception as e:
        return []

@app.get("/stats/history")
def get_history():
    # ... (Same as before)
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        query = """
            SELECT date_trunc('minute', timestamp) as time_chunk, COUNT(*) as count 
            FROM attack_logs 
            WHERE timestamp >= NOW() - INTERVAL '15 minutes'
            GROUP BY time_chunk ORDER BY time_chunk ASC;
        """
        cur.execute(query)
        rows = cur.fetchall()
        conn.close()
        history = []
        for row in rows:
            time_str = row['time_chunk'].strftime("%H:%M")
            history.append({"time": time_str, "attacks": row['count']})
        return history
    except Exception as e:
        return []

@app.get("/stats/map")
def get_map_data():
    # ... (Same as before)
    COUNTRY_COORDS = {
        "China": [105.0, 35.0], "USA": [-100.0, 40.0], "Russia": [100.0, 60.0],
        "Brazil": [-55.0, -10.0], "Germany": [10.0, 51.0], "India": [78.0, 21.0]
    }
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT attacker_ip FROM attack_logs ORDER BY timestamp DESC LIMIT 20")
        rows = cur.fetchall()
        conn.close()
        map_data = []
        for i, row in enumerate(rows):
            ip_tail = int(row['attacker_ip'].split('.')[-1])
            country_names = list(COUNTRY_COORDS.keys())
            country = country_names[ip_tail % len(country_names)]
            coords = COUNTRY_COORDS[country]
            # Add jitter
            map_data.append({
                "name": country,
                "coordinates": [coords[0] + random.uniform(-2,2), coords[1] + random.uniform(-2,2)]
            })
        return map_data
    except Exception as e:
        return []

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)