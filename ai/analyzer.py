from __future__ import annotations
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from ai.providers import analyze_findings, executive_summary
from database.models import AIAnalysis, Vulnerability

def save_per_finding_analysis(db: Session, scan_id: int, vulns: List[Vulnerability], analyses: List[Dict[str, Any]]) -> None:
    # Align by order: vulns correspond to findings order used to create them
    for v, a in zip(vulns, analyses):
        row = AIAnalysis(
            scan_id=scan_id,
            vuln_id=v.id,
            summary=a.get("summary"),
            simple_explanation=a.get("simple_explanation"),
            technical_explanation=a.get("technical_explanation"),
            business_impact=a.get("business_impact"),
            suggested_severity=a.get("suggested_severity"),
            confidence=float(a.get("confidence") or 0.5),
            remediation=a.get("remediation"),
            prevention=a.get("prevention"),
        )
        db.add(row)
    db.commit()

def save_executive_analysis(db: Session, scan_id: int, overall: Dict[str, Any]) -> None:
    row = AIAnalysis(
        scan_id=scan_id,
        vuln_id=None,
        summary=overall.get("executive_summary"),
        simple_explanation=None,
        technical_explanation=None,
        business_impact=None,
        suggested_severity=None,
        confidence=None,
        remediation=None,
        prevention=overall.get("final_conclusion"),
    )
    db.add(row)
    db.commit()

def run_ai_for_scan(db: Session, scan_id: int, target: str, findings: List[Dict[str, Any]], vulns: List[Vulnerability], base_risk: int) -> Dict[str, Any]:
    analyses = analyze_findings(target, findings)
    save_per_finding_analysis(db, scan_id, vulns, analyses)
    overall = executive_summary(target, findings, analyses, base_risk)
    save_executive_analysis(db, scan_id, overall)
    return overall
