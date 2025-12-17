import sys
import os
from sqlalchemy import text

# Add parent directory to path so we can import 'database'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.database import engine, Base
from database.models import Event, AttackSession # 👈 Updated to use new model name

def reset_database():
    print("🗑️  Dropping all existing tables...")
    
    # Drop all tables defined in our models
    Base.metadata.drop_all(bind=engine)
    
    print("✅ Tables dropped.")
    print("🏗️  Creating new tables from models.py...")
    
    # Create them again fresh
    Base.metadata.create_all(bind=engine)
    
    print("✅ Database reset complete! New Schema is active.")

if __name__ == "__main__":
    reset_database()