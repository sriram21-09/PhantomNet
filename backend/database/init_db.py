import sys
import os
from sqlalchemy import create_engine

# Setup path to find 'models'
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from database.models import Base

# REPLACE WITH YOUR REAL PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)

def init_db():
    print("🔄 Connecting to database...")
    Base.metadata.create_all(bind=engine)
    print("✅ Success! All tables (including Sessions) created.")

if __name__ == "__main__":
    init_db()