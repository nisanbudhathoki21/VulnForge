"""
explain_engine.py
------------------
Shared module used by BOTH terminal/dashboard.py and the PDF report
generator. Given a raw finding row (dict, with 'evidence' as a JSON
string or dict), it extracts:

  - the exact endpoint that was hit
  - the exact payload that triggered the finding
  - the HTTP method used
  - a plain-English "what / how / why" explanation a non-technical
    reader (e.g. a teacher) can understand

No network calls, no AI provider calls — pure parsing + templated
explanations, so it's fast, offline, and deterministic.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse, parse_qs, unquote

# ---------------------------------------------------------------------
# Plain-English templates per template_id / name keyword.
# Matched loosely by keyword so new templates still get a sane fallback.
# ---------------------------------------------------------------------
_TEMPLATE_EXPLANATIONS = {
    "xss": {
        "what": "Cross-Site Scripting (XSS)",
        "how": "VulnForge sent a small piece of JavaScript code as input to the site. "
               "Instead of treating it as plain text, the site put it directly into the "
               "page, so the browser ran it as real code.",
        "why": "If a real attacker did this, they could run their own code inside a "
               "victim's browser — for example stealing their login session, or making "
               "the page do things the victim never intended.",
    },
    "sql": {
        "what": "SQL Injection",
        "how": "VulnForge inserted special database syntax (quotes, boolean logic, or "
               "time-delay tricks) into a normal-looking input field or URL parameter. "
               "The application passed this straight into a database query instead of "
               "treating it as plain data.",
        "why": "An attacker could use this to read, change, or delete data in the "
               "database that they were never supposed to access — including other "
               "users' private information.",
    },
    "nosql": {
        "what": "NoSQL Injection",
        "how": "VulnForge sent database operator syntax (like $ne / $gt) instead of a "
               "normal value in a login or query field. The backend treated it as a "
               "database command rather than plain text.",
        "why": "This can let an attacker bypass login checks entirely or pull records "
               "they shouldn't be able to see, without knowing any real password.",
    },
    "command": {
        "what": "OS Command Injection",
        "how": "VulnForge added extra shell syntax (like ; or &&) after a normal-looking "
               "input value. The server ran that extra text as a real system command.",
        "why": "This is one of the most severe issues possible — it can let an attacker "
               "run arbitrary commands on the actual server, not just inside the "
               "website.",
    },
    "upload": {
        "what": "Unrestricted / Bypassed File Upload",
        "how": "VulnForge uploaded a file that should have been rejected (wrong "
               "extension, wrong content-type, or no validation at all), and the "
               "server accepted and stored it anyway.",
        "why": "An attacker could upload a malicious script disguised as a normal file "
               "and get the server to run it, potentially taking over the application.",
    },
    "mime": {
        "what": "MIME Type Validation Bypass",
        "how": "VulnForge changed only the declared file type (Content-Type) of an "
               "upload while keeping the actual file content unsafe, and the server "
               "trusted that label instead of checking the real content.",
        "why": "Attackers can use this trick to sneak dangerous files past filters that "
               "only look at the label, not the actual bytes.",
    },
    "csrf": {
        "what": "Cross-Site Request Forgery (CSRF)",
        "how": "VulnForge found a form or action that changes data but doesn't require "
               "a secret, per-user token to prove the request really came from that "
               "user.",
        "why": "An attacker could trick a logged-in victim into visiting a malicious "
               "page that silently submits actions (like changing settings or making a "
               "purchase) on the victim's behalf.",
    },
    "ssti": {
        "what": "Server-Side Template Injection (SSTI)",
        "how": "VulnForge submitted template syntax (like {{7*7}}) as normal input. If "
               "the server evaluates it instead of displaying it as plain text, that "
               "confirms the input is being run as code on the server.",
        "why": "This can escalate all the way to full remote code execution on the "
               "server, letting an attacker take complete control.",
    },
    "idor": {
        "what": "Insecure Direct Object Reference (IDOR) / Broken Access Control",
        "how": "VulnForge changed an ID or identifier in the request (e.g. someone "
               "else's account/profile ID) while keeping the same login session, and "
               "the server returned that other person's data anyway.",
        "why": "This lets any logged-in user view or modify other users' private data "
               "just by guessing or changing an ID number.",
    },
}

_DEFAULT_EXPLANATION = {
    "what": "Security Weakness",
    "how": "VulnForge sent a crafted request designed to test this specific weakness "
           "and the application responded in a way that confirmed the issue exists.",
    "why": "This could be used by an attacker to affect the confidentiality, integrity, "
           "or availability of the application or its data.",
}


def _match_template(template_id: str, name: str) -> dict:
    key = f"{template_id or ''} {name or ''}".lower()
    for kw, expl in _TEMPLATE_EXPLANATIONS.items():
        if kw in key:
            return expl
    return _DEFAULT_EXPLANATION


def _parse_evidence(evidence_raw) -> dict:
    if isinstance(evidence_raw, dict):
        return evidence_raw
    if not evidence_raw:
        return {}
    try:
        return json.loads(evidence_raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _extract_payload_from_url(url: str) -> str | None:
    """Pull the most suspicious-looking query parameter value out of a URL."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return None

    suspicious_markers = [
        "<script", "alert(", "'", '"', ";", "&&", "|", "$", "{{", "}}",
        "../", "SELECT", "UNION", "OR 1=1", "sleep(",
    ]
    best = None
    for values in qs.values():
        for v in values:
            dv = unquote(v)
            if any(m.lower() in dv.lower() for m in suspicious_markers):
                best = dv
                break
        if best:
            break
    if best:
        return best
    # fall back to raw query string if nothing "matched" but query exists
    if parsed.query:
        return unquote(parsed.query)
    return None


def explain_finding(finding: dict) -> dict:
    """
    Given a finding row (dict with at least name/template_id/evidence),
    return a dict:
        {
          "what": str,
          "how": str,
          "why": str,
          "method": str,
          "endpoint": str,       # base URL without query string
          "full_url": str,
          "payload": str | None, # the exact payload/value that triggered it
          "payload_source": "url" | "body" | "none",
        }
    """
    evidence = _parse_evidence(finding.get("evidence"))
    template_id = finding.get("template_id") or ""
    name = finding.get("name") or ""
    expl = _match_template(template_id, name)

    method = evidence.get("method", "GET") if isinstance(evidence, dict) else "GET"
    full_url = evidence.get("url", "") if isinstance(evidence, dict) else ""
    request_body = evidence.get("request_body", "") if isinstance(evidence, dict) else ""
    response_status = evidence.get("status") if isinstance(evidence, dict) else None
    response_body = evidence.get("response_body", "") if isinstance(evidence, dict) else ""

    try:
        endpoint = full_url.split("?")[0] if full_url else ""
    except Exception:
        endpoint = full_url or ""

    payload = None
    payload_source = "none"

    if request_body and request_body.strip() not in ("", "{}"):
        payload = request_body.strip()
        payload_source = "body"
    else:
        url_payload = _extract_payload_from_url(full_url)
        if url_payload:
            payload = url_payload
            payload_source = "url"

    # Trim the response body to something readable in a small panel,
    # but keep it exact (no rewording) since it's evidence, not prose.
    response_preview = None
    if response_body:
        response_preview = response_body if len(response_body) <= 400 else response_body[:400] + "…"

    return {
        "what": expl["what"],
        "how": expl["how"],
        "why": expl["why"],
        "method": method,
        "endpoint": endpoint or "—",
        "full_url": full_url or "—",
        "payload": payload,
        "payload_source": payload_source,
        "response_status": response_status,
        "response_preview": response_preview,
    }


def explain_findings(findings: list) -> list:
    """Convenience: attach '_explain' to a copy of every finding dict."""
    out = []
    for f in findings:
        f2 = dict(f)
        f2["_explain"] = explain_finding(f)
        out.append(f2)
    return out
