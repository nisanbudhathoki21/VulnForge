from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from database.models import Target, Scan, Vulnerability, Report

def get_or_create_target(db: Session, url: str) -> Target:
    t = db.execute(select(Target).where(Target.url == url)).scalar_one_or_none()
    if t:
        return t
    t = Target(url=url)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t

def create_scan(db: Session, target_id: int, total_templates: int) -> Scan:
    s = Scan(target_id=target_id, total_templates=total_templates, status="running")
    db.add(s)
    db.commit()
    db.refresh(s)
    return s

def finalize_scan(db: Session, scan_id: int, findings_count: int, risk_score: Optional[int] = None) -> None:
    s = db.get(Scan, scan_id)
    if not s:
        return
    s.findings_count = findings_count
    s.finished_at = datetime.utcnow()
    s.status = "completed"
    if risk_score is not None:
        s.risk_score = risk_score
    db.commit()

def add_vulnerability(db: Session, scan_id: int, finding: Dict[str, Any]) -> Vulnerability:
    v = Vulnerability(
        scan_id=scan_id,
        template_id=finding["template_id"],
        name=finding["name"],
        severity=finding["severity"],
        category=finding["category"],
        evidence=finding["evidence"],
        url=finding["url"],
        status_code=int(finding.get("status_code", 0)),
        response_time=float(finding.get("response_time", 0.0)),
        recommendation=finding.get("recommendation", ""),
        status="open",
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    return v

def add_report(db: Session, scan_id: int, path_pdf: str) -> Report:
    r = Report(scan_id=scan_id, path_pdf=path_pdf)
    db.add(r)
    db.commit()
    db.refresh(r)
    return r
