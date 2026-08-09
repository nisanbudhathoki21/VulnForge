#!/usr/bin/env python3
"""
demo_correlation.py — Standalone CorrelationEngine demonstration.

Constructs a realistic set of findings by hand (as if a scan had just
run against a vulnerable target) and runs them through the
CorrelationEngine, printing every InvestigationPath it derives.

This exists so the correlation engine can be demonstrated reliably in
class without depending on a live target, network access, or template
execution timing — the interesting part is the reasoning layer, not the
HTTP requests that feed it.

Run from the project root:
    python3 demo_correlation.py
"""

from workspace.models import Finding, Evidence
from correlation.engine import CorrelationEngine


def make_evidence(id_: str, note: str) -> Evidence:
    return Evidence(
        id=id_,
        request_raw=f"GET {note} HTTP/1.1\nHost: target.local\n",
        response_raw="HTTP/1.1 200 OK\n",
        extracted_data={"note": note},
    )


def build_demo_findings() -> list[Finding]:
    """
    Simulates the output of a scan against a small vulnerable API app.
    The scenario: a weak authentication endpoint, two authenticated API
    endpoints with object-reference issues, and a missing CSP header on
    an endpoint that also has a High-severity finding.
    """
    return [
        Finding(
            id="F-001",
            title="Weak Session Token Generation on /api/auth/login",
            kind="Verified",
            severity="High",
            confidence=0.9,
            category="Authentication",
            context={"url": "http://127.0.0.1:5000/api/auth/login"},
            evidence=[make_evidence("E-001", "/api/auth/login")],
            tags=["auth", "session"],
        ),
        Finding(
            id="F-002",
            title="BOLA: /api/users/{id}/profile returns other users' data",
            kind="Verified",
            severity="High",
            confidence=0.88,
            category="Authorization",
            context={"url": "http://127.0.0.1:5000/api/users/42/profile"},
            evidence=[make_evidence("E-002", "/api/users/42/profile")],
            tags=["bola", "idor"],
        ),
        Finding(
            id="F-003",
            title="BOLA: /api/orders/{id} accessible without ownership check",
            kind="Verified",
            severity="Medium",
            confidence=0.75,
            category="Authorization",
            context={"url": "http://127.0.0.1:5000/api/orders/1057"},
            evidence=[make_evidence("E-003", "/api/orders/1057")],
            tags=["bola", "idor"],
        ),
        Finding(
            id="F-004",
            title="Missing Security Headers (CSP, X-Frame-Options)",
            kind="Verified",
            severity="Low",
            confidence=1.0,
            category="Configuration",
            context={"url": "http://127.0.0.1:5000/dashboard"},
            evidence=[make_evidence("E-004", "/dashboard")],
            tags=["headers"],
        ),
        Finding(
            id="F-005",
            title="Reflected XSS in Search Parameter",
            kind="Verified",
            severity="Critical",
            confidence=0.95,
            category="Injection",
            context={"url": "http://127.0.0.1:5000/dashboard?q=<script>"},
            evidence=[make_evidence("E-005", "/dashboard?q=<script>")],
            tags=["xss"],
        ),
    ]


def print_path(index: int, path) -> None:
    print(f"\n{'=' * 70}")
    print(f"CHAIN #{index}: {path.title}  [{path.pattern}]")
    print(f"{'=' * 70}")
    print(f"Confidence:      {path.confidence:.0%}")
    print(f"Estimated time:  {path.estimated_time}")
    print(f"Findings in chain ({len(path.nodes)}): {', '.join(path.nodes)}")
    print(f"\nReasoning:\n  {path.reasoning}")


def main() -> None:
    findings = build_demo_findings()

    print("VulnForge — Correlation Engine Demo")
    print(f"Input: {len(findings)} raw findings from a simulated scan\n")
    for f in findings:
        print(f"  [{f.id}] {f.severity:<8} {f.title}")

    engine = CorrelationEngine(findings)
    paths = engine.correlate()

    print(f"\n{len(paths)} investigation path(s) derived from correlation:")

    if not paths:
        print("  (none — check that demo findings match the linking rules)")
        return

    for i, path in enumerate(paths, start=1):
        print_path(i, path)

    print(f"\n{'=' * 70}")
    print(
        "Without correlation, these would be reported as "
        f"{len(findings)} independent, disconnected findings.\n"
        f"With correlation, they resolve into {len(paths)} concrete, "
        "reasoned attack narratives an analyst can act on directly."
    )


if __name__ == "__main__":
    main()
