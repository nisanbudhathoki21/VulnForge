"""
Nikto-like fingerprinting + tech detection - Competitive with nikto's checks
Implements:
- Server header fingerprinting (like nikto)
- Known outdated paths (robots.txt, .git, .env, etc) - similar to nikto's 7000 checks but minimal set
- Security headers audit (like nikto + observatory)
- Common misconfiguration signatures
"""
from typing import Dict, List
import re

# Simplified nikto-like database of interesting paths (subset)
NIKTO_INTERESTING_PATHS = [
    ("/.git/HEAD", "Git repository exposed", "high"),
    ("/.env", "Environment file exposed", "critical"),
    ("/.htaccess", "Htaccess file", "low"),
    ("/robots.txt", "Robots.txt", "info"),
    ("/sitemap.xml", "Sitemap", "info"),
    ("/.DS_Store", "DS_Store file", "low"),
    ("/backup.zip", "Backup file", "medium"),
    ("/admin/", "Admin interface", "medium"),
    ("/phpinfo.php", "PHP info", "medium"),
    ("/server-status", "Apache server-status", "medium"),
    ("/.well-known/security.txt", "Security.txt", "info"),
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

SERVER_SIGNATURES = {
    "apache": ["Apache", "2.4.", "2.2."],
    "nginx": ["nginx"],
    "iis": ["IIS", "Microsoft-IIS"],
    "tomcat": ["Tomcat", "Apache Tomcat"],
    "php": ["PHP"],
}

def fingerprint_headers(headers: Dict[str, str]) -> Dict:
    server = headers.get("Server", "Unknown")
    powered = headers.get("X-Powered-By", "")
    tech_stack = []
    for tech, sigs in SERVER_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in server.lower() or sig.lower() in powered.lower():
                tech_stack.append(tech)
                break
    # WAF detection (simplified)
    waf = []
    for h in headers:
        hl = h.lower()
        if "cf-ray" in hl or "cloudflare" in str(headers.get(h,"")).lower():
            waf.append("Cloudflare")
        if "x-sucuri" in hl:
            waf.append("Sucuri")
    missing = [h for h in SECURITY_HEADERS if h not in headers and h.lower() not in [k.lower() for k in headers]]
    return {
        "server": server,
        "powered_by": powered,
        "tech_stack": list(set(tech_stack)),
        "waf": list(set(waf)),
        "missing_headers": missing,
    }

def generate_nikto_templates() -> List[Dict]:
    # Generate synthetic templates for nikto checks (to feed scanner)
    templates=[]
    for path, name, sev in NIKTO_INTERESTING_PATHS:
        templates.append({
            "id": f"nikto-{path.strip('/').replace('.','-').replace('/','-') or 'root'}",
            "name": name,
            "severity": sev,
            "category": "misconfiguration",
            "requests": [{
                "method": "GET",
                "path": [path],
                "matchers": [{"type": "status", "status": [200, 403]}]
            }]
        })
    return templates
