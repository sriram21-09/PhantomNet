from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# ⚠️ CHECK PASSWORD IS CORRECT
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

# 1. Create the engine
engine = create_engine(DATABASE_URL)

# 2. Create the SessionLocal (This is what was missing!)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 3. Create the Base
Base = declarative_base()