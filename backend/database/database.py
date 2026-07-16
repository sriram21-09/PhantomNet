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
            logger.info(f"🔌 Attempting connection to Database...")
            engine = create_engine(
                DATABASE_URL,
                pool_pre_ping=True,  # Auto-detect broken connections
                pool_size=10,
                max_overflow=20,
                connect_args=(
                    {"check_same_thread": False, "timeout": 30}
                    if "sqlite" in DATABASE_URL
                    else {}
                ),
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

    logger.critical(
        "🔥 CRITICAL: Could not connect to Database after multiple attempts."
    )
    raise Exception("Database Connection Failure")


from sqlalchemy import inspect

# Create the engine globally
engine = get_db_engine()

# Dynamically upgrade DB schema if columns are missing
def upgrade_db_schema(engine):
    try:
        inspector = inspect(engine)
        if "packet_logs" in inspector.get_table_names():
            columns = [c["name"] for c in inspector.get_columns("packet_logs")]
            with engine.begin() as conn:
                if "anomaly_score" not in columns:
                    conn.execute(text("ALTER TABLE packet_logs ADD COLUMN anomaly_score FLOAT DEFAULT 0.0"))
                if "mail_from" not in columns:
                    conn.execute(text("ALTER TABLE packet_logs ADD COLUMN mail_from VARCHAR(256)"))
                if "rcpt_to" not in columns:
                    conn.execute(text("ALTER TABLE packet_logs ADD COLUMN rcpt_to VARCHAR(256)"))
                if "email_subject" not in columns:
                    conn.execute(text("ALTER TABLE packet_logs ADD COLUMN email_subject VARCHAR(512)"))
                if "body_len" not in columns:
                    conn.execute(text("ALTER TABLE packet_logs ADD COLUMN body_len INTEGER"))

        if "sentinel_playbooks" in inspector.get_table_names():
            sp_columns = [c["name"] for c in inspector.get_columns("sentinel_playbooks")]
            with engine.begin() as conn:
                if "llm_narrative" not in sp_columns:
                    conn.execute(text("ALTER TABLE sentinel_playbooks ADD COLUMN llm_narrative TEXT"))
                    logger.info("✅ Database schema migration: added llm_narrative to sentinel_playbooks")

        if "system_config" in inspector.get_table_names():
            sc_columns = [c["name"] for c in inspector.get_columns("system_config")]
            with engine.begin() as conn:
                if "sentinel_llm_enabled" not in sc_columns:
                    conn.execute(text("ALTER TABLE system_config ADD COLUMN sentinel_llm_enabled BOOLEAN DEFAULT 0"))
                    logger.info("✅ Database schema migration: added sentinel_llm_enabled to system_config")
    except Exception as e:
        logger.warning(f"Schema upgrade check failed/skipped: {e}")

upgrade_db_schema(engine)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
