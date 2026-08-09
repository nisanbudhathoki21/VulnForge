# Security Research Report — cct.edu.np

**Scan ID:** `10e502ed-dfab-4a70-a3ff-5e5b7062d8d9`  
**Date:** August 06, 2026  
**Total Findings:** 1

---

## 1. Missing Security Headers

**Severity:** Medium  
**Kind:** Possible  
**Category:** Headers

### Executive Summary

Testing against `cct.edu.np` identified a **Missing Security Headers** issue classified under **Headers**. This finding is currently rated **Possible** and requires manual verification before being submitted as a confirmed vulnerability.

### Affected Asset

- **Domain:** cct.edu.np
- **Endpoint:** `https://cct.edu.np/`
- **Environment:** Production

### Observed Behavior

Missing: content-security-policy | Missing: x-frame-options | Missing: strict-transport-security | Missing: x-content-type-options

### Steps to Reproduce

1. Send a request to the affected endpoint:
   ```
   curl -is -X GET 'https://cct.edu.np/'
   ```
2. Inspect the response headers/body for the evidence described above.

### Proof of Concept (PoC)

```bash
curl -is -X GET 'https://cct.edu.np/'
```

### Impact

This is a **potential** issue based on automated detection. It has not been manually verified and should not be reported as a confirmed vulnerability until validated by a human researcher.

---

_Findings labeled `Possible` or `Investigation` require manual verification before being reported as confirmed vulnerabilities._
