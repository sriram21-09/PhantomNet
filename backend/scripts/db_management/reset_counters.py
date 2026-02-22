import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

def reset_database():
    load_dotenv()
    DATABASE_URL = os.getenv("DATABASE_URL")
    if not DATABASE_URL:
        print("❌ DATABASE_URL not found.")
        return

    print(f"🧹 Resetting database: {DATABASE_URL}")
    try:
        engine = create_engine(DATABASE_URL)
        tables = ['packet_logs', 'traffic_stats', 'attack_sessions', 'events']
        
        with engine.connect() as conn:
            for table in tables:
                print(f"   - Truncating {table}...")
                conn.execute(text(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE"))
            conn.commit()
        print("✅ All tables truncated and identities reset.")
    except Exception as e:
        print(f"❌ Error resetting database: {e}")

if __name__ == "__main__":
    reset_database()
