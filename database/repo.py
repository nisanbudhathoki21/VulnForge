from .session import SessionLocal
from .models import DBFinding

class FindingRepository:
    @staticmethod
    def save_finding(scan_id, finding_obj):
        db = SessionLocal()
        try:
            new_finding = DBFinding(
                scan_id=scan_id,
                title=finding_obj.title,
                severity=finding_obj.severity,
                url=finding_obj.context.get("url"),
                evidence=finding_obj.context.get("evidence"),
                poc=f"curl -is -X GET '{finding_obj.context.get('url')}'"
            )
            db.add(new_finding)
            db.commit()
        finally:
            db.close()
