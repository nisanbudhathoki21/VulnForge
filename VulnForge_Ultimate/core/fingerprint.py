#!/usr/bin/env python3
"""
Advanced fingerprinting – detects WAF, CDN, server, DB, frameworks, security tools.
"""

import requests
import re
import hashlib
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


class Fingerprint:
    def __init__(self, url, timeout=8, probe_paths=True):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.probe_paths = probe_paths
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.results = {
            'server': 'Unknown',
            'waf': [],
            'cdn': [],
            'tech_stack': [],
            'cms': [],
            'frameworks': [],
            'libraries': [],
            'databases': [],
            'security_tools': [],
            'os': 'Unknown',
            'security_headers': {},
            'security_rating': 'N/A',
            'favicon_hash': None,
            'response_code': None,
            'content_type': None,
            'scan_timestamp': datetime.now().isoformat(),
        }
        self.probe_paths_list = [
            '/wp-admin', '/wp-json', '/administrator', '/admin',
            '/api/health', '/phpinfo', '/phpinfo.php', '/server-status',
            '/.env', '/package.json', '/composer.json', '/robots.txt',
            '/sitemap.xml', '/favicon.ico', '/.git/HEAD', '/.aws/credentials',
            '/.well-known/security.txt',
        ]
        self._probe_results = {}

    def _safe_request(self, path, method='GET', **kwargs):
        url = urljoin(self.url, path) if not path.startswith('http') else path
        try:
            return self.session.request(method, url, timeout=self.timeout,
                                        allow_redirects=True, **kwargs)
        except Exception:
            return None

    def _get_favicon_hash(self):
        resp = self._safe_request('/favicon.ico')
        if resp and resp.status_code == 200 and len(resp.content) > 0:
            hash_md5 = hashlib.md5(resp.content).hexdigest()
            self.results['favicon_hash'] = hash_md5
            cms_hashes = {
                'wordpress': 'f420dc2c7d90d7873a90d82cd7fde315',
                'joomla': 'a8c4b5eaf0e6c3e7c9e4d8f0e3a5b2c1',
                'drupal': '3b2b1f1e9d4c5b6a7f8e9d0c1b2a3f4e',
            }
            for cms, h in cms_hashes.items():
                if h == hash_md5:
                    self.results['cms'].append(cms.title())
                    break

    def _detect_server(self, headers):
        server = headers.get('Server', '')
        if server:
            self.results['server'] = server
            if 'nginx' in server.lower():
                self.results['os'] = 'Linux/Unix'
            elif 'apache' in server.lower():
                self.results['os'] = 'Linux/Unix'
            elif 'iis' in server.lower():
                self.results['os'] = 'Windows'
            elif 'cloudflare' in server.lower():
                self.results['os'] = 'Cloudflare Proxy'
        elif 'X-Powered-By' in headers:
            self.results['server'] = headers['X-Powered-By']

    def _detect_waf_cdn(self, headers, cookies, body):
        signatures = {
            'Cloudflare': (
                ['cf-ray', 'cf-cache-status'], ['__cfduid', 'cf_clearance'], ['Cloudflare']
            ),
            'AWS WAF': (
                ['x-amzn-requestid', 'x-amzn-errortype'], ['aws-waf-token'], ['AWS WAF']
            ),
            'Sucuri': (
                ['x-sucuri-id', 'x-sucuri-cache'], ['sucuri'], ['Sucuri WebSite Firewall']
            ),
            'Akamai': (
                ['x-akamai-transformed', 'x-akamai-session'], ['_abck', 'bm_sz'], ['Akamai']
            ),
            'ModSecurity': (['x-mod-security'], [], ['ModSecurity', 'mod_security']),
            'Imperva': (
                ['x-cdn', 'x-protect', 'x-iinfo'], ['incap_ses', 'visid_incap'], ['Imperva']
            ),
            'F5 BIG-IP': (['x-waas'], ['BIGipServer'], ['F5', 'BIG-IP']),
            'Wordfence': (['x-wordfence'], ['wfvt_', 'wf_'], ['Wordfence']),
            'CloudFront': (['x-amz-cf-id', 'x-amz-cf-pop'], [], ['CloudFront']),
            'Fastly': (['x-served-by', 'x-cache'], [], ['Fastly']),
            'Varnish': (['x-varnish', 'x-cache'], [], ['Varnish']),
            'Barracuda': (['x-barracuda'], [], ['Barracuda']),
            'NSFocus': (['x-nsfocus'], [], ['NSFocus']),
            'Yandex': (['x-yandex'], [], ['Yandex']),
            'SiteLock': (['x-sitelock'], [], ['SiteLock']),
            'Microsoft Azure Front Door': (['x-azure-ref'], [], ['Azure']),
            'Google Cloud Armor': (['x-google-backend'], [], ['Google Cloud Armor']),
        }
        detected = set()
        headers_str = ' '.join([f'{k}:{v}' for k, v in headers.items()]).lower()
        cookies_str = ' '.join([f'{k}={v}' for k, v in cookies.items()]).lower()
        body_lower = body[:3000].lower() if body else ''

        for name, (hpat, cpat, bpat) in signatures.items():
            for h in hpat:
                if h.lower() in headers_str:
                    detected.add(name)
                    break
            else:
                for c in cpat:
                    if c.lower() in cookies_str:
                        detected.add(name)
                        break
                else:
                    for b in bpat:
                        if b.lower() in body_lower:
                            detected.add(name)
                            break

        cdn_set = {d for d in detected if d in ['Cloudflare', 'CloudFront', 'Akamai',
                                                  'Fastly', 'Varnish', 'Microsoft Azure Front Door']}
        waf_set = detected - cdn_set
        self.results['waf'] = list(waf_set)
        self.results['cdn'] = list(cdn_set)

    def _detect_tech_from_body(self, body, headers):
        tech_stack = []
        cms = []
        frameworks = []
        libraries = []
        databases = []
        security_tools = []

        # Headers
        powered = headers.get('X-Powered-By', '').lower()
        if 'php' in powered: tech_stack.append('PHP')
        if 'asp.net' in powered: tech_stack.append('ASP.NET')
        if 'node' in powered: tech_stack.append('Node.js')
        if 'express' in powered: frameworks.append('Express')
        if 'laravel' in powered: frameworks.append('Laravel')

        gen = headers.get('X-Generator', '').lower()
        if 'wordpress' in gen: cms.append('WordPress')
        if 'drupal' in gen: cms.append('Drupal')
        if 'joomla' in gen: cms.append('Joomla')

        # Cookies
        cookies_str = ' '.join([f'{k}={v}' for k, v in self.session.cookies.items()]).lower()
        if 'laravel_session' in cookies_str: frameworks.append('Laravel')
        if 'django' in cookies_str: frameworks.append('Django')
        if 'rails' in cookies_str: frameworks.append('Ruby on Rails')
        if 'wordpress' in cookies_str or 'wp-' in cookies_str: cms.append('WordPress')

        # Body patterns
        body_lower = body.lower()
        # CMS
        if 'wordpress' in body_lower or 'wp-content' in body_lower: cms.append('WordPress')
        if 'joomla' in body_lower: cms.append('Joomla')
        if 'drupal' in body_lower: cms.append('Drupal')
        if 'magento' in body_lower: cms.append('Magento')
        if 'shopify' in body_lower: cms.append('Shopify')

        # Frameworks
        if 'laravel' in body_lower: frameworks.append('Laravel')
        if 'django' in body_lower: frameworks.append('Django')
        if 'rails' in body_lower or 'ruby on rails' in body_lower: frameworks.append('Ruby on Rails')
        if 'express' in body_lower: frameworks.append('Express')
        if 'spring' in body_lower: frameworks.append('Spring Boot')
        if 'flask' in body_lower: frameworks.append('Flask')

        # Libraries
        if 'jquery' in body_lower: libraries.append('jQuery')
        if 'react' in body_lower: libraries.append('React')
        if 'vue' in body_lower: libraries.append('Vue.js')
        if 'angular' in body_lower: libraries.append('Angular')
        if 'bootstrap' in body_lower: libraries.append('Bootstrap')

        # Databases (from error messages or specific strings)
        if 'mysql' in body_lower or 'SQLSTATE' in body_lower: databases.append('MySQL')
        if 'postgresql' in body_lower or 'pg_' in body_lower: databases.append('PostgreSQL')
        if 'mongodb' in body_lower or 'MongoError' in body_lower: databases.append('MongoDB')
        if 'redis' in body_lower: databases.append('Redis')
        if 'elasticsearch' in body_lower: databases.append('Elasticsearch')

        # Security tools (Sentry, New Relic, etc.)
        if 'sentry' in body_lower or 'sentry-trace' in headers: security_tools.append('Sentry')
        if 'newrelic' in body_lower or 'x-newrelic' in headers: security_tools.append('New Relic')
        if 'datadog' in body_lower or 'x-datadog' in headers: security_tools.append('Datadog')
        if 'bugsnag' in body_lower: security_tools.append('Bugsnag')

        self.results['tech_stack'] = list(set(tech_stack))
        self.results['cms'] = list(set(cms))
        self.results['frameworks'] = list(set(frameworks))
        self.results['libraries'] = list(set(libraries))
        self.results['databases'] = list(set(databases))
        self.results['security_tools'] = list(set(security_tools))

    def _detect_security_headers(self, headers):
        required = {
            'Content-Security-Policy': 'Content-Security-Policy',
            'X-Frame-Options': 'X-Frame-Options',
            'Strict-Transport-Security': 'Strict-Transport-Security',
            'X-Content-Type-Options': 'X-Content-Type-Options',
            'Referrer-Policy': 'Referrer-Policy',
            'Permissions-Policy': 'Permissions-Policy',
            'X-XSS-Protection': 'X-XSS-Protection'
        }
        found = {}
        for header, value in required.items():
            found[header] = headers.get(header)
        self.results['security_headers'] = found
        present = sum(1 for v in found.values() if v is not None)
        if present >= 7: rating = 'A'
        elif present >= 5: rating = 'B'
        elif present >= 3: rating = 'C'
        elif present >= 1: rating = 'D'
        else: rating = 'F'
        self.results['security_rating'] = rating

    def _probe_paths(self):
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self._safe_request, path): path
                       for path in self.probe_paths_list}
            for future in as_completed(futures):
                path = futures[future]
                resp = future.result()
                if resp:
                    self._probe_results[path] = resp
                    if path == '/wp-json':
                        try:
                            if 'routes' in resp.json():
                                self.results['cms'].append('WordPress (REST)')
                        except: pass
                    if path == '/.env' and 'DB_' in resp.text:
                        self.results['databases'].extend(['MySQL', 'PostgreSQL'])

    def run(self):
        resp = self._safe_request(self.url)
        if not resp:
            return self.results
        headers = resp.headers
        body = resp.text
        cookies = resp.cookies
        self.results['response_code'] = resp.status_code
        self.results['content_type'] = headers.get('Content-Type', '')
        self._detect_server(headers)
        self._detect_waf_cdn(headers, cookies, body)
        self._detect_tech_from_body(body, headers)
        self._detect_security_headers(headers)
        self._get_favicon_hash()
        if self.probe_paths:
            self._probe_paths()
        # Deduplicate
        for key in ['cms', 'frameworks', 'libraries', 'databases', 'security_tools', 'tech_stack']:
            self.results[key] = list(set(self.results[key]))
        return self.results


def fingerprint_target(url, quiet=False):
    fp = Fingerprint(url)
    result = fp.run()
    if not quiet:
        print("\n[FINGERPRINT]")
        print(f"  Server: {result['server']}")
        if result['waf']: print(f"  WAF: {', '.join(result['waf'])}")
        if result['cdn']: print(f"  CDN: {', '.join(result['cdn'])}")
        if result['tech_stack']: print(f"  Tech Stack: {', '.join(result['tech_stack'])}")
        if result['cms']: print(f"  CMS: {', '.join(result['cms'])}")
        if result['frameworks']: print(f"  Frameworks: {', '.join(result['frameworks'])}")
        if result['libraries']: print(f"  Libraries: {', '.join(result['libraries'])}")
        if result['databases']: print(f"  Databases: {', '.join(result['databases'])}")
        if result['security_tools']: print(f"  Security Tools: {', '.join(result['security_tools'])}")
        print(f"  OS: {result['os']}")
        print(f"  Security Rating: {result['security_rating']}")
        print("")
    return result
