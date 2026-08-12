# How to make VulnForge competitive with nuclei, nikto, advanced regex & differential scanners

This guide is for https://github.com/nisanbudhathoki21/VulnForge

All fixed files are in `/home/user/VulnForge_Patched/` (ready to copy). Patch notes detailed in `VulnForge_Patched/PATCH_NOTES.md`.

## QUICK FIX (apply patches)

```bash
cd /home/user/VulnForge

# backup
git checkout -b fix/competitive-patch
cp -r VulnForge VulnForge_backup 2>/dev/null; true

# apply core fixes
cp ../VulnForge_Patched/engine/scanner.py engine/scanner.py
cp ../VulnForge_Patched/engine/template_runtime.py engine/template_runtime.py
cp ../VulnForge_Patched/core/differential.py core/differential.py
cp ../VulnForge_Patched/matcher/engine.py matcher/engine.py
cp ../VulnForge_Patched/extractor/engine.py extractor/engine.py
cp ../VulnForge_Patched/httpclient/client.py httpclient/client.py
cp ../VulnForge_Patched/templates/loader.py templates/loader.py
cp ../VulnForge_Patched/correlation/engine.py correlation/engine.py

# add new competitive modules
cp ../VulnForge_Patched/engine/interactsh.py engine/interactsh.py
cp ../VulnForge_Patched/engine/nikto_fingerprint.py engine/nikto_fingerprint.py
cp ../VulnForge_Patched/engine/advanced_dsl.py engine/advanced_dsl.py

# update requirements
cat > requirements.txt <<'REQ'
httpx[http2]>=0.27.0
PyYAML>=6.0.2
requests>=2.31.0
colorama>=0.4.6
lxml>=4.9.3
beautifulsoup4>=4.12.0
tldextract>=5.1.0
reportlab>=5.0.0
jsonpath-ng>=1.6.0
brotli>=1.1.0
rich>=13.0.0
REQ

python -m py_compile engine/scanner.py core/differential.py matcher/engine.py
python tests/test_scanner_runtime.py
python tests/test_template_execution.py

# push
git add -A
git commit -m "fix: competitive patch - session reuse, matchers (time/header_absent/dsl/size), differential, regex cache, interactsh, nikto fingerprint"
git push origin fix/competitive-patch
```

## WHAT WAS WRONG (summary for README)

See `VulnForge_Patched/PATCH_NOTES.md` full report. Top 3:

1. **Session recreation bug** killed auth & speed
2. **Missing time matcher** => blind SQLi, SSRF time-based never detected
3. **Header absent matcher missing** => security headers (nikto-style) never fired

## COMPETITIVE ROADMAP

To beat nuclei/nikto long term:

- Port 100+ CVE templates from nuclei-templates repo (use converter script)
- Add crawler like Katana (JS link finder + form parsing already partly done, enhance)
- Add real interactsh server integration (use https://github.com/projectdiscovery/interactsh)
- Add rate limiter with jitter already fixed, but add `aiolimiter` for async scanner
- Export SARIF for GitHub CI integration like nikto
- Severity threshold flag `--severity critical,high` like nuclei `-severity`
- Tags filter `--tags sqli,xss` like nuclei
- Improve dashboard to show correlation chains (auth->api takeover etc)

## DEMO COMMANDS (after patch)

```bash
# Fast scan like nuclei
python main.py -u http://testphp.vulnweb.com --threads 20 --delay 0 --rate-limit 0 -q

# With nikto-style fingerprint
python - <<'PY'
from engine.nikto_fingerprint import fingerprint_headers
print(fingerprint_headers({"Server":"Apache/2.4.41","X-Powered-By":"PHP/7.4"}))
PY

# Test differential
python - <<'PY'
from core.differential import ResponseFingerprint, compare_boolean_responses
b=ResponseFingerprint(200, 1000, "normal page", 0.3)
t=ResponseFingerprint(200, 1000, "normal page with user", 0.3)
f=ResponseFingerprint(200, 1200, "different page no user", 0.3)
print(compare_boolean_responses(b,t,f).reason)
PY
```

