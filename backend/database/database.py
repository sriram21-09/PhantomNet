import time
import logging
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
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

# Resolve relative SQLite paths dynamically based on the project structure
if DATABASE_URL.startswith("sqlite:///"):
    db_path = DATABASE_URL[10:]
    if not os.path.isabs(db_path) and not db_path.startswith("/"):
        db_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        project_root = os.path.dirname(db_dir)
        
        if db_path.startswith("backend/"):
            db_file_clean = db_path[len("backend/"):]
            absolute_db_path = os.path.abspath(os.path.join(db_dir, db_file_clean))
        else:
            absolute_db_path = os.path.abspath(os.path.join(project_root, db_path))
            
        # Standardize path separators for SQLAlchemy
        absolute_db_path = absolute_db_path.replace("\\", "/")
        DATABASE_URL = f"sqlite:///{absolute_db_path}"

# SQLite WAL mode registration on Engine connect event
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if type(dbapi_connection).__module__ in ('sqlite3', 'pysqlite2.dbapi2'):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        finally:
            cursor.close()



def get_db_engine():
    """
    Attempts to connect to the DB with retries.
    Fixes [Task 1]: Investigate/Fix connection issues.
    Fixes [Task 2]: Improve error messages.
    """
    retries = 3
    while retries > 0:
        try:
            logger.info("🔌 Attempting connection to Database...")

            # BUG-15 fix: Use appropriate pool settings per engine
            if "sqlite" in DATABASE_URL:
                connect_args = {"check_same_thread": False, "timeout": 30}
                engine = create_engine(
                    DATABASE_URL,
                    pool_pre_ping=True,
                    connect_args=connect_args,
                )
            else:
                engine = create_engine(
                    DATABASE_URL,
                    pool_pre_ping=True,
                    pool_size=50,
                    max_overflow=100,
                )
            # Test connection
            with engine.connect() as connection:
                logger.info("✅ Database Connection ESTABLISHED.")
            return engine

        except OperationalError as e:
            retries -= 1
            logger.error("❌ Connection Failed: %s", e)
            logger.warning("⚠️  Retrying in 2 seconds... (%d attempts left)", retries)
            time.sleep(2)

    logger.critical(
        "🔥 CRITICAL: Could not connect to Database after multiple attempts."
    )
    raise Exception("Database Connection Failure")


from sqlalchemy import inspect

# Create the engine globally
engine = get_db_engine()

# Dynamic schema migration is deprecated in favor of Alembic migrations (GOV-01).
# Kept for backward compatibility but disabled at import time.
def upgrade_db_schema(engine):
    """
    Deprecated: Schema migrations are managed by Alembic.
    To upgrade the database schema, run `alembic upgrade head`.
    """
    logger.info("ℹ️ Database schema management handled via Alembic migrations.")

# In V3, migrations are strictly managed via Alembic (alembic upgrade head).

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
