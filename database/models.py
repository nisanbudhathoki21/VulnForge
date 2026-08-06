from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class DBFinding(Base):
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(100))
    title = Column(String(200))
    severity = Column(String(50))
    url = Column(Text)
    evidence = Column(Text)
    poc = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
