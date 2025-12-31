from sqlalchemy import create_engine, inspect
import os

# Use env var with safe fallback
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./phantomnet_ci.db"
)

def check_db():
    try:
        engine = create_engine(DATABASE_URL)
        inspector = inspect(engine)
        tables = inspector.get_table_names()

        print("\n--- RESULTS ---")
        if "events" in tables or "packet_logs" in tables:
            print("✅ SUCCESS: Required tables found.")
            print("Verification PASSED.")
        else:
            print(f"❌ INCOMPLETE. Found tables: {tables}")

    except Exception as e:
        print(f"❌ ERROR: Could not connect. {e}")

if __name__ == "__main__":
    check_db()
