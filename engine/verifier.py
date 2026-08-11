import json
import re
from typing import Dict, Any

def evaluate_and_confirm_finding(finding: Dict[str, Any], response_status: int, response_headers: Dict[str, str], response_body: str) -> Dict[str, Any]:
    headers_lower = {k.lower(): v for k, v in response_headers.items()}
    content_type = headers_lower.get("content-type", "").lower()
    
    # 1. Security Headers (Deterministic Confirmed)
    if "security header" in finding.get("vuln_type", "").lower() or "clickjacking" in finding.get("vuln_type", "").lower():
        finding["is_confirmed"] = True
        finding["status"] = "CONFIRMED"
        finding["confidence"] = 1.0
        return finding
        
    # 2. Mass Assignment JSON Body Check
    if "mass assignment" in finding.get("vuln_type", "").lower():
        if response_status in [200, 201] and "text/html" not in content_type:
            try:
                data = json.loads(response_body)
                user_data = data.get("data", data)
                if isinstance(user_data, dict) and (user_data.get("role") == "admin" or user_data.get("isAdmin") is True):
                    finding["is_confirmed"] = True
                    finding["status"] = "CONFIRMED"
                    finding["confidence"] = 1.0
                    finding["verification_proof"] = f"Server accepted elevated parameter and returned role='admin' in response: {json.dumps(user_data)[:120]}"
                    return finding
            except Exception:
                pass

    # 3. Sensitive Files (.env, .git, .key)
    if any(ext in finding.get("endpoint", "") for ext in [".env", ".git", ".key", ".sql", ".bak"]):
        if "text/html" in content_type:
            finding["is_confirmed"] = False
            finding["status"] = "UNCONFIRMED"
            finding["confidence"] = 0.0
            return finding
            
        sig_pattern = finding.get("signature_regex", r"(?:DB_PASSWORD|DB_HOST|APP_KEY|ref:\s+refs/)")
        if re.search(sig_pattern, response_body, re.IGNORECASE):
            finding["is_confirmed"] = True
            finding["status"] = "CONFIRMED"
            finding["confidence"] = 1.0
            return finding

    # 4. General Confidence >= 0.80
    if finding.get("confidence", 0) >= 0.80 or finding.get("verified") is True:
        finding["is_confirmed"] = True
        finding["status"] = "CONFIRMED"
        finding["confidence"] = 1.0
        return finding

    finding["is_confirmed"] = False
    finding["status"] = "UNCONFIRMED"
    return finding
