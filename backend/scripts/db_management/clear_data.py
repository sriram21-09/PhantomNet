import os
import sys
from sqlalchemy import create_engine, text
from database.models import PacketLog
from dotenv import load_dotenv

# Setup path
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, '.env')
load_dotenv(env_path)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("❌ DATABASE_URL not found.")
    sys.exit(1)

# 1. Clear Database
print("🧹 Clearing PostgreSQL Database...")
try:
    engine = create_engine(DATABASE_URL)
    with engine.connect() as connection:
        connection.execute(text("TRUNCATE TABLE packet_logs RESTART IDENTITY CASCADE"))
        connection.commit()
    print("✅ Database cleared (packet_logs truncated).")
except Exception as e:
    print(f"❌ Error clearing database: {e}")

# 2. Clear Log Files
print("🧹 Clearing Log Files...")
LOG_DIR = os.path.join(current_dir, "logs")
if os.path.exists(LOG_DIR):
    for filename in os.listdir(LOG_DIR):
        file_path = os.path.join(LOG_DIR, filename)
        if os.path.isfile(file_path) and (filename.endswith(".jsonl") or filename.endswith(".log")):
            try:
                with open(file_path, 'w') as f:
                    f.truncate(0)
                print(f"   - Cleared {filename}")
            except Exception as e:
                print(f"   ❌ Failed to clear {filename}: {e}")
else:
    print("   ⚠️ Log directory not found.")

print("✨ All data cleared successfully!")
