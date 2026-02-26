import time
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
from .models import Base
import os
from dotenv import load_dotenv

# Setup Professional Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhantomNet-DB")

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phantomnet.db")

def get_db_engine():
    """
    Attempts to connect to the DB with retries.
    Fixes [Task 1]: Investigate/Fix connection issues.
    Fixes [Task 2]: Improve error messages.
    """
    retries = 3
    while retries > 0:
        try:
            logger.info(f"🔌 Attempting connection to Database...")
            engine = create_engine(
                DATABASE_URL, 
                pool_pre_ping=True, # Auto-detect broken connections
                pool_size=10, 
                max_overflow=20,
                connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
            )
            # Test connection
            with engine.connect() as connection:
                logger.info("✅ Database Connection ESTABLISHED.")
            return engine
        
        except OperationalError as e:
            retries -= 1
            logger.error(f"❌ Connection Failed: {e}")
            logger.warning(f"⚠️  Retrying in 2 seconds... ({retries} attempts left)")
            time.sleep(2)
    
    logger.critical("🔥 CRITICAL: Could not connect to Database after multiple attempts.")
    raise Exception("Database Connection Failure")

# Create the engine globally
engine = get_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
