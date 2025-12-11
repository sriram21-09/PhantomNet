import sys
import os
from sqlalchemy import create_engine

# Setup paths to import models
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from database.models import Base, Session

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)

def fix_table():
    print("🛠️  Fixing Sessions table...")
    
    # 1. Drop the old table (Delete it)
    try:
        Session.__table__.drop(engine)
        print("🗑️  Old table dropped.")
    except Exception as e:
        print(f"⚠️  Table didn't exist, skipping drop.")

    # 2. Create the new table (with event_count)
    Base.metadata.create_all(bind=engine)
    print("✅ Success! New Sessions table created with 'event_count'.")

if __name__ == "__main__":
    fix_table()