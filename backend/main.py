from models import Base, PacketLog
# Database Engine
if DATABASE_URL:
    try:
        engine = create_engine(DATABASE_URL)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        # ⚡ Auto-create tables with new Indexes
        Base.metadata.create_all(bind=engine)
        print("✅ Database Schema & Indexes Verified")
    except Exception as e:
        print(f"⚠️ Database Connection Error: {e}")