from sqlalchemy import create_engine, text

# REPLACE 'YOUR_PASSWORD' BELOW
DATABASE_URL = "postgresql://postgres:Luckky@localhost:5432/phantomnet_db"

def test_connection():
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            print("\n✅ Connection successful")
            print("Database is reachable.")
    except Exception as e:
        print("\n❌ Connection failed")
        print(f"Error: {e}")

if __name__ == "__main__":
    test_connection()