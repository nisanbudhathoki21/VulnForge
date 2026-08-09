"""
correlation/engine.py — VulnForge Correlation Engine

Links individually-reported findings into higher-order attack chains.

A template-based scanner reports isolated signals: "missing header here",
"BOLA there". On their own, none of these individually may look severe.
The value of correlation is recognising that an attacker doesn't see
isolated signals — they see a path. This module builds a graph of
relationships between findings using a small set of explicit rules, then
walks that graph to emit InvestigationPath objects: concrete, reasoned
attack narratives a human analyst can act on directly.

Design principles:
    * Every linking rule is isolated in its own method and documented with
      the security reasoning behind it — this is the part a reviewer
      should be able to audit rule-by-rule.
    * Confidence is a computed function of chain evidence (finding count,
      severity mix, presence of confirmed/exploited findings), not a
      hand-picked constant. See `_compute_confidence` for the exact model.
    * Path generation and graph linking are separate concerns: linking
      rules populate `self.graph`; path generators read from it. Adding a
      new path pattern should not require touching the linking rules,
      and vice versa.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Tuple

from workspace.models import Finding, FindingKind


# ---------------------------------------------------------------------------
# Confidence model
# ---------------------------------------------------------------------------

# Weight given to each additional linked finding beyond the first two
# (diminishing returns — a 6-finding chain isn't 3x as certain as a
# 2-finding chain, but it is more certain).
_CHAIN_SIZE_WEIGHT = 0.06
_MAX_CHAIN_SIZE_BONUS = 0.20

# Severity contributes to confidence because a chain built from
# High/Critical findings represents a more concrete, higher-stakes path
# than one built from informational signals.
_SEVERITY_WEIGHT = {
    "Critical": 0.15,
    "High": 0.10,
    "Medium": 0.05,
    "Low": 0.0,
    "Info": 0.0,
}

# A finding that has actually been confirmed or successfully exploited is
# no longer a hypothesis — it's evidence. Chains containing one are more
# trustworthy than chains built purely from pattern matches.
_CONFIRMED_BONUS = 0.10
_EXPLOITED_BONUS = 0.15

_BASE_CONFIDENCE = 0.45
_MAX_CONFIDENCE = 0.97


@dataclass
class InvestigationPath:
    title: str
    reasoning: str
    estimated_time: str
    nodes: List[str]  # Finding IDs
    confidence: float
    pattern: str = ""  # short machine-readable pattern id, e.g. "api-cluster"


class CorrelationEngine:
    """Links findings into actionable, reasoned attack chains."""

    def __init__(self, findings: List[Finding]):
        self.findings: Dict[str, Finding] = {f.id: f for f in findings}
        self.graph: Dict[str, Set[str]] = {f.id: set() for f in findings}
        self.paths: List[InvestigationPath] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self) -> List[InvestigationPath]:
        """Build the relationship graph, then derive investigation paths."""
        self._link_by_endpoint()
        self._link_by_risk_amplification()
        self._link_auth_dependencies()

        self.paths = self._generate_investigation_paths()
        return self.paths

    # ------------------------------------------------------------------
    # Linking rules
    #
    # Each rule adds directed edges to self.graph. Rules are additive and
    # independent — order does not matter, and a finding may participate
    # in multiple rules simultaneously.
    # ------------------------------------------------------------------

    def _link_by_endpoint(self) -> None:
        """Rule: findings on the same endpoint are related.

        An attacker attacking one endpoint will naturally discover and use
        every weakness on that endpoint together, regardless of what
        template originally flagged each one.
        """
        endpoints: Dict[str, List[str]] = {}
        for f_id, f in self.findings.items():
            url = f.context.get("url", "unknown")
            endpoints.setdefault(url, []).append(f_id)

        for f_ids in endpoints.values():
            for i in f_ids:
                for j in f_ids:
                    if i != j:
                        self.graph[i].add(j)

    def _link_by_risk_amplification(self) -> None:
        """Rule: foundational weaknesses amplify active vulnerabilities.

        A missing security header (e.g. CSP, HSTS) rarely scores as
        severe on its own, but it directly widens the blast radius of a
        co-located High/Critical finding — e.g. no CSP turns a borderline
        XSS into full script execution. We link foundational findings to
        every high-impact finding so that amplification is visible even
        when they weren't caught by the same endpoint rule.
        """
        foundationals = [
            f for f in self.findings.values() if "headers" in f.title.lower()
        ]
        vulnerabilities = [
            f for f in self.findings.values() if f.severity in ("High", "Critical")
        ]

        for f in foundationals:
            for v in vulnerabilities:
                if f.id != v.id:
                    self.graph[f.id].add(v.id)

    def _link_auth_dependencies(self) -> None:
        """Rule: authentication findings link to every finding gated by auth.

        A single authentication weakness (broken login, weak session
        handling, missing rate limiting) doesn't just stand on its own —
        it is the key that unlocks every authenticated endpoint the scan
        found. We link each auth finding to every /api/ finding so a
        downstream path generator can recognise "weak auth + N gated
        endpoints" as a single compound risk.
        """
        auth_issues = [
            f for f in self.findings.values() if f.category == "Authentication"
        ]
        api_findings = [
            f for f in self.findings.values() if "/api/" in str(f.context.get("url"))
        ]

        for a in auth_issues:
            for api in api_findings:
                if a.id != api.id:
                    self.graph[a.id].add(api.id)

    # ------------------------------------------------------------------
    # Confidence model
    # ------------------------------------------------------------------

    def _compute_confidence(self, node_ids: List[str]) -> float:
        """Derive a confidence score from the evidence in a chain.

        Confidence is not a guess about exploitability — it is a measure
        of how much concrete evidence supports treating this chain as a
        single risk, based on: how many findings participate, how severe
        they are, and whether any have moved beyond "pattern matched" to
        "confirmed" or "exploited".
        """
        nodes = [self.findings[n] for n in node_ids if n in self.findings]
        if not nodes:
            return 0.0

        score = _BASE_CONFIDENCE

        chain_bonus = min(
            _MAX_CHAIN_SIZE_BONUS, max(0, len(nodes) - 2) * _CHAIN_SIZE_WEIGHT
        )
        score += chain_bonus

        best_severity_weight = max(
            (_SEVERITY_WEIGHT.get(n.severity, 0.0) for n in nodes), default=0.0
        )
        score += best_severity_weight

        if any(getattr(n, "confirmed", False) for n in nodes):
            score += _CONFIRMED_BONUS
        if any(getattr(n, "exploit_success", False) for n in nodes):
            score += _EXPLOITED_BONUS

        return round(min(_MAX_CONFIDENCE, score), 2)

    # ------------------------------------------------------------------
    # Path generation
    #
    # Each generator reads from self.graph / self.findings and produces
    # zero or more InvestigationPath objects. Generators are independent
    # and additive — adding a new pattern means adding a new method and
    # calling it here, nothing else needs to change.
    # ------------------------------------------------------------------

    def _generate_investigation_paths(self) -> List[InvestigationPath]:
        paths: List[InvestigationPath] = []
        paths.extend(self._path_api_cluster())
        paths.extend(self._path_foundation_amplification())
        paths.extend(self._path_auth_to_api_takeover())
        return paths

    def _path_api_cluster(self) -> List[InvestigationPath]:
        """Multiple findings on /api/ endpoints suggest systemic BOLA risk.

        OWASP API Security Top 10 #1 (Broken Object Level Authorization)
        is rarely caught by a single template match — it emerges from
        seeing the same authorization gap repeated across endpoints.
        """
        api_chain = [
            f_id for f_id, f in self.findings.items() if "/api/" in str(f.context.get("url"))
        ]
        if len(api_chain) <= 1:
            return []

        return [
            InvestigationPath(
                title="API Security Deep-Dive",
                reasoning=(
                    f"{len(api_chain)} related signals were found across API "
                    "endpoints. This pattern is consistent with Broken Object "
                    "Level Authorization (OWASP API Top 10 #1) — worth manually "
                    "testing object ID substitution across these endpoints."
                ),
                estimated_time="45 mins",
                nodes=api_chain,
                confidence=self._compute_confidence(api_chain),
                pattern="api-cluster",
            )
        ]

    def _path_foundation_amplification(self) -> List[InvestigationPath]:
        """Missing headers alongside a High/Critical finding raise its ceiling."""
        header_issues = [
            f_id for f_id, f in self.findings.items() if "headers" in f.title.lower()
        ]
        high_sev = [
            f_id for f_id, f in self.findings.items() if f.severity in ("High", "Critical")
        ]

        if not (header_issues and high_sev):
            return []

        nodes = header_issues + high_sev
        return [
            InvestigationPath(
                title="Exploit Chain: Foundation Weakness",
                reasoning=(
                    "Missing security headers were found alongside "
                    f"{len(high_sev)} High/Critical finding(s). Weak headers "
                    "(e.g. absent CSP) can remove the last line of defence "
                    "against these vulnerabilities being fully exploitable "
                    "in a real browser session."
                ),
                estimated_time="30 mins",
                nodes=nodes,
                confidence=self._compute_confidence(nodes),
                pattern="foundation-amplification",
            )
        ]

    def _path_auth_to_api_takeover(self) -> List[InvestigationPath]:
        """A weak-auth finding chained to gated API findings = account takeover risk.

        This closes the gap left by `_link_auth_dependencies`: that rule
        builds the graph edges, but until now nothing read them back out
        into a reported path. An attacker who can bypass or weaken
        authentication doesn't just gain "one more finding" — they gain
        access to every authenticated endpoint the scan already flagged.
        This pattern surfaces that compound risk explicitly, rather than
        leaving the analyst to notice it themselves.
        """
        auth_issues = [
            f for f in self.findings.values() if f.category == "Authentication"
        ]
        if not auth_issues:
            return []

        results: List[InvestigationPath] = []
        for auth in auth_issues:
            gated = sorted(self.graph.get(auth.id, set()))
            gated = [n for n in gated if "/api/" in str(self.findings[n].context.get("url"))]
            if not gated:
                continue

            nodes = [auth.id] + gated
            results.append(
                InvestigationPath(
                    title="Exploit Chain: Auth Bypass to API Takeover",
                    reasoning=(
                        f"'{auth.title}' was found alongside {len(gated)} "
                        "authenticated API finding(s). If the authentication "
                        "weakness is exploitable, it likely grants access to "
                        "every gated endpoint below it — turning a single "
                        "auth issue into full API compromise. Prioritise "
                        "confirming the auth finding first; it is the key "
                        "that unlocks the rest of this chain."
                    ),
                    estimated_time="60 mins",
                    nodes=nodes,
                    confidence=self._compute_confidence(nodes),
                    pattern="auth-to-api-takeover",
                )
            )

        return results
