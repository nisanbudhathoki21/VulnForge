from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.settings import Settings
from database.models import Base

def get_engine():
    db_url = f"sqlite:///{Settings().DB_PATH}"
    return create_engine(db_url, echo=False, future=True)

Engine = get_engine()
SessionLocal = sessionmaker(bind=Engine, autoflush=False, autocommit=False, future=True)

def init_db() -> None:
    Base.metadata.create_all(bind=Engine)
