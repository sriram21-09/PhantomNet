from sqlalchemy import create_engine, inspect

# REPLACE 'YOUR_PASSWORD' BELOW
DATABASE_URL = DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"
def check_db():
    try:
        engine = create_engine(DATABASE_URL)
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        print("\n--- RESULTS ---")
        if 'events' in tables and 'sessions' in tables:
            print("✅ SUCCESS: Found tables 'events' and 'sessions'.")
            print("Day 1 is COMPLETE.")
        else:
            print(f"❌ INCOMPLETE. Found tables: {tables}")
            
    except Exception as e:
        print(f"❌ ERROR: Could not connect. {e}")

if __name__ == "__main__":
    check_db()