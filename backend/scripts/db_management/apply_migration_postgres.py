import sys
import os
from sqlalchemy import text

# Add backend to path to import database module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from database.database import get_db_engine

# Resolve absolute path to SQL file relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQL_PATH = os.path.join(BASE_DIR, "database", "migrations", "add_threat_scores.sql")

def apply_migration():
    engine = get_db_engine()
    print(f"Connected to DB: {engine.url}")
    
    with open(SQL_PATH, 'r') as f:
        # Split by ';' to get individual statements if needed, 
        # but executescript logic varies. 
        # Let's read the file.
        sql_content = f.read()

    # Split statements because sqlalchemy execute might not handle multiple statements in one go for some drivers
    # But for Postgres it usually does if configured.
    # Safer to split by ';'
    statements = [s.strip() for s in sql_content.split(';') if s.strip()]
    
    with engine.connect() as conn:
        for stmt in statements:
            print(f"Executing: {stmt[:50]}...")
            try:
                conn.execute(text(stmt))
                conn.commit() # Commit each DDL
                print("Success.")
            except Exception as e:
                print(f"Error executing statement: {e}")
                # Don't exit, might be "column already exists"
                
    print("Migration finished.")

if __name__ == "__main__":
    apply_migration()
