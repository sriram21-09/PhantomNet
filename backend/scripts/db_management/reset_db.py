import sys
import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Add backend root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from database.models import Base

# Load .env
load_dotenv(os.path.join(os.path.dirname(__file__), "../../.env"))

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("❌ DATABASE_URL not found in .env")
    sys.exit(1)

engine = create_engine(DATABASE_URL)

print("💥 DESTROYING old tables...")
# This deletes the old, incorrect tables
Base.metadata.drop_all(bind=engine)

print("🏗️ CREATING new tables...")
# This creates the new tables with 'session_token'
Base.metadata.create_all(bind=engine)

print("✅ Database Reset Complete!")
