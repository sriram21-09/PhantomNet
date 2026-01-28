from database import engine
from sqlalchemy import text
import os

def apply_migration():
    migration_file = 'db/migrations/002_add_smtp_fields.sql'
    
    print(f"🔄 Reading migration file: {migration_file}...")
    
    if not os.path.exists(migration_file):
        print(f"❌ Error: File not found at {migration_file}")
        return

    try:
        with open(migration_file, 'r') as f:
            sql_script = f.read()
        
        # Connect, Execute, and Commit in one transaction
        with engine.connect() as connection:
            print("🔌 Connected to Database. Executing SQL...")
            connection.execute(text(sql_script))
            connection.commit()
            print("✅ Migration Complete: SMTP columns added successfully.")
            
    except Exception as e:
        print(f"❌ Migration Failed: {e}")

if __name__ == "__main__":
    apply_migration()