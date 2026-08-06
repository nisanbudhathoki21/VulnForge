from .session import SessionLocal
from .models import DBFinding, DBInvestigationPath


class FindingRepository:

    @staticmethod
    def save_scan(scan_id, findings, investigation_paths):
        """Persist all findings and investigation paths for a scan, linked together."""
        db = SessionLocal()
        try:
            # Save investigation paths first so we have their DB ids to link back to findings
            path_id_by_finding_uuid = {}
            db_paths = []

            for path in investigation_paths:
                db_path = DBInvestigationPath(
                    scan_id=scan_id,
                    title=path.title,
                    reasoning=path.reasoning,
                    estimated_time=path.estimated_time,
                    confidence=path.confidence,
                )
                db.add(db_path)
                db.flush()  # assigns db_path.id without committing yet
                db_paths.append(db_path)

                for finding_uuid in path.nodes:
                    path_id_by_finding_uuid[finding_uuid] = db_path.id

            for f in findings:
                db.add(DBFinding(
                    finding_uuid=f.id,
                    scan_id=scan_id,
                    title=f.title,
                    severity=f.severity,
                    kind=f.kind,
                    category=f.category,
                    url=f.context.get("url"),
                    evidence=f.context.get("evidence"),
                    poc=f"curl -is -X GET '{f.context.get('url')}'",
                    investigation_id=path_id_by_finding_uuid.get(f.id),
                ))

            db.commit()
        finally:
            db.close()
