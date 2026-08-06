from sqlalchemy import Column, Integer, String, DateTime, Text, Float, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()


class DBFinding(Base):
    __tablename__ = 'findings'

    id = Column(Integer, primary_key=True)
    finding_uuid = Column(String(100))   # matches Finding.id from workspace.models
    scan_id = Column(String(100))
    title = Column(String(200))
    severity = Column(String(50))
    kind = Column(String(50))
    category = Column(String(100))
    url = Column(Text)
    evidence = Column(Text)
    poc = Column(Text)
    investigation_id = Column(Integer, ForeignKey('investigation_paths.id'), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("DBInvestigationPath", back_populates="findings")


class DBInvestigationPath(Base):
    __tablename__ = 'investigation_paths'

    id = Column(Integer, primary_key=True)
    scan_id = Column(String(100))
    title = Column(String(200))
    reasoning = Column(Text)
    estimated_time = Column(String(50))
    confidence = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

    findings = relationship("DBFinding", back_populates="investigation")
