from sqlalchemy import create_engine, text
from database.models import Base

# ⚠️ REPLACE WITH YOUR PASSWORD
DATABASE_URL = "postgresql://postgres:Luckky@phantomnet_postgres:5432/phantomnet_db"

engine = create_engine(DATABASE_URL)

print("💥 DESTROYING old tables...")
# This deletes the old, incorrect tables
Base.metadata.drop_all(bind=engine)

print("🏗️ CREATING new tables...")
# This creates the new tables with 'session_token'
Base.metadata.create_all(bind=engine)

print("✅ Database Reset Complete!")
