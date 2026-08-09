#!/usr/bin/env python3
"""
core/verifier.py – Dynamic verification of vulnerabilities.
"""

import time
import re
import json
from urllib.parse import urljoin
from typing import Dict, Any, List, Optional
from core.heuristics import HeuristicAnalyzer


class Verifier:
    def __init__(self, session, base_url, quiet=False):
        self.session = session
        self.base_url = base_url
        self.quiet = quiet

    def verify(self, finding: Dict, template: Dict) -> Dict:
        """
        Run verification steps for a finding.
        Returns a dict with:
          - verified: bool
          - verification_evidence: str
          - confidence: float
        """
        # 1. Heuristic analysis
        evidence = finding.get('evidence', {})
        heuristic = HeuristicAnalyzer.analyze(evidence, finding.get('template_id', 'generic'))
        confidence = heuristic['confidence']
        reasons = heuristic['reasons']

        # 2. If confidence is already very low, skip verification
        if confidence < 0.3:
            return {
                'verified': False,
                'verification_evidence': 'Low heuristic confidence; likely false positive',
                'confidence': confidence,
                'reasons': reasons
            }

        # 3. Run template‑specific verification if available
        verification_steps = template.get('verification', [])
        if verification_steps:
            # Reuse the scanner's verification logic (we'll pass it to the scanner)
            # We just need to signal that verification succeeded.
            # This will be handled in the scanner's _execute_template.
            pass

        # 4. If no verification steps, use generic checks
        if not verification_steps:
            # For API endpoints: check if response body is valid JSON
            body = evidence.get('response_body', '')
            try:
                json.loads(body)
                confidence += 0.1
                reasons.append("Valid JSON response")
            except:
                if '<html' in body:
                    confidence -= 0.2
                    reasons.append("HTML response – likely false positive")

        # 5. Final decision
        verified = confidence >= 0.7
        return {
            'verified': verified,
            'verification_evidence': body[:500],
            'confidence': confidence,
            'reasons': reasons
        }
