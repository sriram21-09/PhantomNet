import os
import sys
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Setup path to find .env
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, '.env')
load_dotenv(env_path)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("DATABASE_URL not found in .env") 
    sys.exit(1)

print(f"Connecting to: {DATABASE_URL}")

try:
    engine = create_engine(DATABASE_URL)
    with engine.connect() as connection:
        # Check packet_logs count
        result = connection.execute(text("SELECT COUNT(*) FROM packet_logs"))
        count = result.scalar()
        print(f"Total PacketLog records: {count}")
        
        # Check table size (approximate)
        size_query = text("SELECT pg_size_pretty(pg_total_relation_size('packet_logs'))")
        size = connection.execute(size_query).scalar()
        print(f"Table Size: {size}")

except Exception as e:
    print(f"Error: {e}")
