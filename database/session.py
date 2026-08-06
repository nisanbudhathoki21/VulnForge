from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base

# Using SQLite for local research persistence
engine = create_engine('sqlite:///vulnforge.db', connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
