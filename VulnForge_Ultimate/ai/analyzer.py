from __future__ import annotations

from typing import Dict, Any, List, Optional

from ai.providers import NullAI, AIProvider


def _provider_or_default(provider: Optional[AIProvider] = None) -> AIProvider:
    """
    Return the supplied AI provider or the built-in NullAI provider.
    """
    return provider if provider is not None else NullAI()


def analyze_finding(
    finding: Dict[str, Any],
    provider: Optional[AIProvider] = None,
) -> Dict[str, Any]:
    """
    Analyze one VulnForge finding using the configured AI provider.

    This function performs no database operations.
    """

    ai = _provider_or_default(provider)

    try:
        summary = ai.summarize(finding)
    except Exception as exc:
        summary = f"AI summary unavailable: {exc}"

    try:
        guidance = ai.guidance(finding)
    except Exception as exc:
        guidance = f"AI guidance unavailable: {exc}"

    return {
        "summary": summary,
        "guidance": guidance,
        "provider": getattr(ai, "name", "unknown"),
    }


def analyze_findings(
    findings: List[Dict[str, Any]],
    provider: Optional[AIProvider] = None,
) -> List[Dict[str, Any]]:
    """
    Analyze all findings.

    Returns one analysis dictionary for every finding.
    """

    results: List[Dict[str, Any]] = []

    for finding in findings:
        results.append(
            analyze_finding(
                finding=finding,
                provider=provider,
            )
        )

    return results


def build_executive_summary(
    target: str,
    findings: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build a deterministic executive summary.

    This does not pretend to be AI-generated. It summarizes the
    scanner's actual findings and their severity.
    """

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "info")
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["info"] += 1

    total = len(findings)

    if total == 0:
        summary = (
            f"VulnForge completed a security scan of {target}. "
            "No findings were recorded."
        )
    else:
        summary = (
            f"VulnForge completed a security scan of {target} "
            f"and recorded {total} finding"
            f"{'s' if total != 1 else ''}. "
            f"The scan identified "
            f"{severity_counts['critical']} critical, "
            f"{severity_counts['high']} high, "
            f"{severity_counts['medium']} medium, "
            f"{severity_counts['low']} low, and "
            f"{severity_counts['info']} informational findings."
        )

    conclusion = (
        "Findings should be manually validated before being treated "
        "as confirmed security vulnerabilities."
    )

    return {
        "target": target,
        "finding_count": total,
        "severity_counts": severity_counts,
        "executive_summary": summary,
        "final_conclusion": conclusion,
        "analyses_count": len(analyses),
    }


def run_ai_for_scan(
    target: str,
    findings: List[Dict[str, Any]],
    provider: Optional[AIProvider] = None,
) -> Dict[str, Any]:
    """
    Run the AI-analysis layer for a scan.

    Database persistence is intentionally handled elsewhere by
    core.database. This keeps the AI layer independent of the
    storage implementation.
    """

    analyses = analyze_findings(
        findings=findings,
        provider=provider,
    )

    overall = build_executive_summary(
        target=target,
        findings=findings,
        analyses=analyses,
    )

    return {
        "findings": analyses,
        "executive": overall,
    }


__all__ = [
    "analyze_finding",
    "analyze_findings",
    "build_executive_summary",
    "run_ai_for_scan",
]
