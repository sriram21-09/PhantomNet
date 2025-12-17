from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Update this line if your password/db name is different
# Format: postgresql://user:password@localhost/dbname
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:Luckky@localhost/phantomnet"

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()