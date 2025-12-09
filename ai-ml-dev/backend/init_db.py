import sys
import os
from sqlalchemy import create_engine

# Fix imports to find the 'database' module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.models import Base

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:lUCKKY@localhost:5432/phantomnet_db"

def init_db():
    try:
        print("Connecting to database...")
        engine = create_engine(DATABASE_URL)
        print("Creating tables...")
        Base.metadata.create_all(engine)
        print("✅ Success! Tables created.")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    init_db()