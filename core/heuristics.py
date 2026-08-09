#!/usr/bin/env python3
"""
core/heuristics.py – Heuristic analysis engine for zero‑false‑positive detection.
"""

import re
from typing import Dict, Any, List

FALSE_POSITIVE_INDICATORS = [
    r'<html',
    r'<!DOCTYPE',
    r'CloudFront',
    r'Fastly',
    r'Varnish',
    r'OpsTools',
    r'checking your browser',
    r'captcha',
    r'access denied',
    r'cf-challenge',
    r'one moment, please',
    r'please wait',
    r'maintenance',
]

REAL_BUG_INDICATORS = [
    # JSON API responses
    r'application/json',
    r'text/plain',
    r'{"',
    r'"email"',
    r'"id"',
    r'"success":true',
    # SQL errors
    r'SQLSTATE',
    r'MySQL',
    r'PostgreSQL',
    r'ORA-',
    # XSS
    r'<script>',
    r'onerror=',
    r'alert\(',
    # SSTI
    r'49',  # For ${7*7}
    r'root:x:0',  # For /etc/passwd
]

class HeuristicAnalyzer:
    @staticmethod
    def analyze(response: Dict, finding_type: str = 'generic') -> Dict:
        """
        Analyze a response and return:
          - confidence: float 0.0-1.0
          - reasons: list of reasons for the score
        """
        confidence = 0.5  # neutral start
        reasons = []

        body = response.get('response_body', '')
        headers = response.get('response_headers', {})
        status = response.get('status', 0)

        # 1. Check for false positive indicators
        for pattern in FALSE_POSITIVE_INDICATORS:
            if re.search(pattern, body, re.I):
                confidence -= 0.15
                reasons.append(f"False positive indicator: {pattern}")
                if confidence < 0:
                    confidence = 0.0

        # 2. Check for real bug indicators
        for pattern in REAL_BUG_INDICATORS:
            if re.search(pattern, body, re.I):
                confidence += 0.1
                reasons.append(f"Real bug indicator: {pattern}")

        # 3. Content‑Type checks
        ct = headers.get('Content-Type', '')
        if 'application/json' in ct:
            confidence += 0.2
            reasons.append("JSON response (likely API)")
        elif 'text/plain' in ct:
            confidence += 0.1
            reasons.append("Plain text response")
        elif 'text/html' in ct and finding_type in ['env', 'git', 'api']:
            confidence -= 0.3
            reasons.append("HTML response when API expected")

        # 4. Status code heuristics
        if status in [200, 201, 204]:
            confidence += 0.05
        elif status in [302, 303, 307]:
            confidence -= 0.1
            reasons.append("Redirect may be false positive")

        # 5. Check for known good data
        if finding_type == 'bola':
            if '"email"' in body or '"id"' in body:
                confidence += 0.2
                reasons.append("Contains user identifiers")
        elif finding_type == 'sql':
            if any(x in body for x in ['SQL', 'mysql', 'error']):
                confidence += 0.3
                reasons.append("SQL error detected")
        elif finding_type == 'xss':
            if '<script>' in body and 'alert' in body:
                confidence += 0.4
                reasons.append("Script execution reflected")

        # 6. Cap confidence
        confidence = max(0.0, min(1.0, confidence))

        return {
            'confidence': confidence,
            'reasons': reasons,
            'score_level': 'high' if confidence > 0.7 else 'medium' if confidence > 0.4 else 'low'
        }
