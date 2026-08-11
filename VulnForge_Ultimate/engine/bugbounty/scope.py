"""
Bug Bounty Scope Manager - Professional grade
Handles HackerOne/Bugcrowd style scopes: *.target.com, target.com, etc
Enforces in-scope/out-of-scope, respects BBP rules.
More advanced than nuclei's scope (which is just regex).
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Set
from urllib.parse import urlparse
import tldextract

@dataclass
class ScopeRule:
    pattern: str
    is_wildcard: bool
    is_in_scope: bool
    regex: re.Pattern

class BugBountyScope:
    """
    Professional scope enforcement for bug bounty hunting.
    Supports:
    - *.example.com
    - example.com
    - *.sub.example.com
    - https://example.com/api/*
    - out-of-scope patterns
    """
    def __init__(self, in_scope: List[str], out_of_scope: List[str] = None):
        self.in_scope_raw = in_scope or []
        self.out_scope_raw = out_of_scope or []
        self.in_rules: List[ScopeRule] = []
        self.out_rules: List[ScopeRule] = []
        self._parse_rules()

    def _parse_rules(self):
        for pat in self.in_scope_raw:
            self.in_rules.append(self._compile_rule(pat, True))
        for pat in self.out_scope_raw:
            self.out_rules.append(self._compile_rule(pat, False))

    def _compile_rule(self, pattern: str, is_in: bool) -> ScopeRule:
        pat = pattern.strip().lower()
        is_wildcard = pattern.startswith("*.")
        # Convert wildcard to regex
        # *.example.com -> ^([a-z0-9-]+\.)*example\.com$
        # Also handle path wildcards: example.com/api/* -> ^example\.com\/api\/.*$
        regex_pat = pat
        if is_wildcard:
            # Remove *.
            base = pat[2:]  # example.com
            # Escape dots
            base_escaped = re.escape(base)
            regex_pat = rf"^([a-z0-9-]+\.)*{base_escaped}$"
        else:
            # If contains *, convert
            if "*" in pat:
                regex_pat = re.escape(pat).replace(r"\*", ".*")
                regex_pat = f"^{regex_pat}$"
            else:
                # Exact domain or URL
                # Extract host if URL provided
                if "://" in pat:
                    try:
                        host = urlparse(pat).netloc.lower()
                        regex_pat = f"^{re.escape(host)}$"
                    except:
                        regex_pat = f"^{re.escape(pat)}$"
                else:
                    # Allow subdomains for non-wildcard? For bug bounty, example.com means example.com AND *.example.com? 
                    # We make it configurable: here exact match, but we provide option to include subdomains
                    regex_pat = f"^{re.escape(pat)}$"
        
        try:
            compiled = re.compile(regex_pat, re.I)
        except re.error:
            compiled = re.compile(rf"^{re.escape(pat)}$", re.I)
        
        return ScopeRule(pattern=pat, is_wildcard=is_wildcard, is_in_scope=is_in, regex=compiled)

    def _host_from_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or parsed.netloc or url).lower()
            return host
        except:
            return url.lower()

    def is_in_scope(self, url: str) -> bool:
        host = self._host_from_url(url)
        # First check out-of-scope - always wins
        for rule in self.out_rules:
            if rule.regex.search(host) or rule.regex.search(url.lower()):
                return False
        
        # If no in-scope rules defined, allow all (except out-of-scope)
        if not self.in_rules:
            return True
        
        # Check in-scope
        for rule in self.in_rules:
            # For wildcard rules, also check exact parent domain
            if rule.is_wildcard:
                # *.example.com should also allow example.com itself?
                # Many BBP include parent, we do
                base = rule.pattern[2:]  # example.com
                if host == base:
                    return True
            if rule.regex.search(host) or rule.regex.search(url.lower()):
                return True
        
        return False

    def filter_urls(self, urls: List[str]) -> List[str]:
        return [u for u in urls if self.is_in_scope(u)]

    def get_root_domains(self) -> Set[str]:
        roots = set()
        for pat in self.in_scope_raw:
            # Extract root via tldextract
            try:
                ext = tldextract.extract(pat)
                if ext.domain and ext.suffix:
                    roots.add(f"{ext.domain}.{ext.suffix}")
            except:
                pass
        return roots

# Example usage for bug bounty hunter
if __name__ == "__main__":
    scope = BugBountyScope(
        in_scope=["*.example.com", "example.com", "https://api.example.com/*"],
        out_of_scope=["*.out.example.com", "admin.example.com"]
    )
    tests = [
        "https://sub.example.com/page",
        "https://example.com",
        "https://admin.example.com",
        "https://out.example.com",
        "https://evil.com"
    ]
    for t in tests:
        print(t, "->", scope.is_in_scope(t))
