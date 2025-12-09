from sqlalchemy import create_engine
from database.models import Base
# IMPORTANT: Replace YOUR_PASSWORD with your real Postgres password below
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

def init_db():
    try:
        engine = create_engine(DATABASE_URL)
        print("Creating tables...")
        Base.metadata.create_all(engine)
        print("Success! Tables 'events' and 'sessions' created successfully.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    init_db()