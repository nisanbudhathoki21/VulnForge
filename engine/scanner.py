#!/usr/bin/env python3
"""
engine/scanner.py – Full God‑Level Scanner (handles missing deps gracefully)
"""

import os
import re
import yaml
import json
import time
import requests
import traceback
import zlib
import random
import string
from urllib.parse import urljoin, urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional imports with fallback
try:
    import brotli
except ImportError:
    brotli = None

try:
    import jsonpath_ng
except ImportError:
    jsonpath_ng = None


class WAFBypass:
    def __init__(self, proxy_file=None, user_agent_list=None):
        self.proxies = []
        self.user_agents = user_agent_list or [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        ]
        self.current_index = 0
        if proxy_file and os.path.isfile(proxy_file):
            with open(proxy_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    proxy_url = parts[0]
                    country = parts[1] if len(parts) > 1 else 'XX'
                    self.proxies.append((proxy_url, country))

    def get_proxy(self, preferred_country=None):
        if not self.proxies:
            return None
        if preferred_country:
            country_proxies = [p for p in self.proxies if p[1].upper() == preferred_country.upper()]
            if country_proxies:
                proxy = random.choice(country_proxies)
                return {'http': proxy[0], 'https': proxy[0]}
        self.current_index = (self.current_index + 1) % len(self.proxies)
        proxy_url = self.proxies[self.current_index][0]
        return {'http': proxy_url, 'https': proxy_url}

    def get_headers(self):
        fake_ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.9']),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'X-Forwarded-For': fake_ip,
            'X-Real-IP': fake_ip,
            'X-Originating-IP': fake_ip,
            'CF-Connecting-IP': fake_ip,
            'True-Client-IP': fake_ip,
        }

    def get_user_agent(self):
        return random.choice(self.user_agents)

    def get_delay(self, base_delay, jitter=0.5):
        return base_delay + random.uniform(0, jitter)


class AuthManager:
    def __init__(self, session, base_url, quiet=False):
        self.session = session
        self.base_url = base_url
        self.quiet = quiet
        self.authenticated = False
        self.auth_data = {
            'jwt': None,
            'cookies': {},
            'headers': {},
            'username': None,
            'password': None,
            'user_id': None,
        }
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        if self.domain.startswith('www.'):
            self.domain = self.domain[4:]

    def generate_email(self, prefix='scanner'):
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"{prefix}_{rand}@{self.domain}"

    def generate_password(self, base='VulnForge2024!'):
        domain_part = self.domain.split('.')[0] if '.' in self.domain else self.domain
        return f"{base}{domain_part.capitalize()}{random.randint(10,99)}!"

    def register(self, email=None, password=None):
        if not email:
            email = self.generate_email()
        if not password:
            password = self.generate_password()
        reg_endpoints = [
            '/api/Users', '/api/users', '/register', '/signup',
            '/auth/register', '/rest/register', '/json/register'
        ]
        for endpoint in reg_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                data = {'email': email, 'password': password, 'passwordRepeat': password}
                resp = self.session.post(url, json=data)
                if resp.status_code in [200, 201]:
                    self.auth_data['username'] = email
                    self.auth_data['password'] = password
                    return True
                resp = self.session.post(url, data=data)
                if resp.status_code in [200, 201, 302]:
                    self.auth_data['username'] = email
                    self.auth_data['password'] = password
                    return True
            except:
                continue
        return False

    def login(self, username=None, password=None):
        if username is None:
            username = self.auth_data.get('username')
        if password is None:
            password = self.auth_data.get('password')
        if not username or not password:
            return False
        login_endpoints = [
            '/rest/user/login', '/api/login', '/auth/login',
            '/login', '/signin', '/json/login'
        ]
        for endpoint in login_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                resp = self.session.post(url, json={'email': username, 'password': password})
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if 'token' in data:
                            self.auth_data['jwt'] = data['token']
                            self.session.headers['Authorization'] = f'Bearer {data["token"]}'
                            self.authenticated = True
                            return True
                        if 'authentication' in data and 'token' in data['authentication']:
                            self.auth_data['jwt'] = data['authentication']['token']
                            self.session.headers['Authorization'] = f'Bearer {data["authentication"]["token"]}'
                            self.authenticated = True
                            return True
                    except:
                        pass
                resp = self.session.post(url, data={'username': username, 'password': password})
                if resp.status_code in [200, 302]:
                    if self.session.cookies.get_dict():
                        self.authenticated = True
                        return True
            except:
                continue
        return False

    def authenticate(self, username=None, password=None):
        if not username:
            if self.register():
                return self.login()
        else:
            self.auth_data['username'] = username
            self.auth_data['password'] = password
            return self.login()
        return False


class Scanner:
    def __init__(self, url, quiet=False, template_dir='templates/',
                 max_workers=10, proxy_file=None, country=None,
                 rate_limit=0, delay=2, jitter=0.5, exploit=False,
                 username=None, password=None, timeout=10,
                 skip_priv=False, skip_auth=False):
        self.raw_url = url.rstrip('/')
        if not self.raw_url.startswith(('http://', 'https://')):
            self.raw_url = 'https://' + self.raw_url
        parsed = urlparse(self.raw_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.quiet = quiet
        self.template_dir = template_dir
        self.max_workers = max_workers
        self.proxy_file = proxy_file
        self.preferred_country = country
        self.rate_limit = rate_limit
        self.base_delay = delay
        self.jitter = jitter
        self.exploit_enabled = exploit
        self.timeout = timeout
        self.skip_priv = skip_priv
        self.skip_auth = skip_auth
        self.last_request_time = 0

        self.waf = WAFBypass(proxy_file=self.proxy_file)
        self.session = self._get_session()
        self.auth = AuthManager(self.session, self.base_url, self.quiet)
        self.username = username
        self.password = password

        self.context = {
            'BaseURL': self.base_url,
            'interactsh-url': 'oob.vulnforge.com',
        }
        self.templates = []
        self.findings = []
        self.scan_id = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]

        self.block_patterns = [
            'cf-challenge', 'one moment, please', 'checking your browser',
            'captcha', 'cloudflare', 'ddos protection', 'please wait',
            'access denied', 'cf-ray', 'shutdown', 'site is down',
            'offline', 'maintenance mode', 'under maintenance',
        ]

    def _get_session(self):
        sess = requests.Session()
        sess.headers.update(self.waf.get_headers())
        sess.headers['User-Agent'] = self.waf.get_user_agent()
        proxy = self.waf.get_proxy(self.preferred_country)
        if proxy:
            sess.proxies = proxy
        return sess

    def _throttle(self, retry=False):
        if self.rate_limit > 0:
            interval = 1.0 / self.rate_limit
            elapsed = time.time() - self.last_request_time
            if elapsed < interval:
                sleep_time = interval - elapsed
                if retry:
                    sleep_time = sleep_time * 2
                time.sleep(sleep_time)
        if self.base_delay > 0:
            delay = self.waf.get_delay(self.base_delay, self.jitter)
            time.sleep(delay)
        self.last_request_time = time.time()

    def _decode_response_body(self, response):
        content_encoding = response.headers.get('Content-Encoding', '').lower()
        raw_content = response.content
        if content_encoding == 'br' and brotli:
            try:
                raw_content = brotli.decompress(raw_content)
            except:
                pass
        elif content_encoding in ('gzip', 'deflate'):
            try:
                if content_encoding == 'gzip':
                    raw_content = zlib.decompress(raw_content, 16 + zlib.MAX_WBITS)
                else:
                    raw_content = zlib.decompress(raw_content)
            except:
                pass
        try:
            return raw_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                return raw_content.decode('latin-1')
            except:
                return raw_content.decode('utf-8', errors='ignore')

    def load_templates(self):
        if os.path.isfile(self.template_dir):
            try:
                with open(self.template_dir, 'r') as f:
                    data = yaml.safe_load(f)
                if data and isinstance(data, dict) and 'id' in data:
                    if 'requests' not in data or not isinstance(data['requests'], list):
                        return
                    data['_file'] = self.template_dir
                    self.templates.append(data)
                    if not self.quiet:
                        print(f"[LOADING] {self.template_dir} -> {data.get('id', 'unknown')}")
            except:
                pass
        else:
            if not os.path.isdir(self.template_dir):
                return
            for root, _, files in os.walk(self.template_dir):
                for file in files:
                    if file.endswith(('.yaml', '.yml')):
                        path = os.path.join(root, file)
                        try:
                            with open(path, 'r') as f:
                                data = yaml.safe_load(f)
                            if data and isinstance(data, dict) and 'id' in data:
                                if 'requests' not in data or not isinstance(data['requests'], list):
                                    continue
                                data['_file'] = path
                                self.templates.append(data)
                                if not self.quiet:
                                    print(f"[LOADING] {path} -> {data.get('id', 'unknown')}")
                        except:
                            pass

    def _substitute(self, value, extra_context=None):
        if extra_context is None:
            extra_context = {}
        ctx = {**self.context, **extra_context}
        ctx.update(self.auth.auth_data)
        def replace(match):
            expr = match.group(1).strip()
            if any(op in expr for op in ['+', '-', '*', '/']):
                try:
                    allowed = {
                        'int': int, 'float': float, 'str': str, 'len': len,
                        'random': random.randint,
                    }
                    for k, v in ctx.items():
                        if isinstance(v, (int, float, str, bool, list)):
                            allowed[k] = v
                    return str(eval(expr, {"__builtins__": {}}, allowed))
                except:
                    return match.group(0)
            if expr in ctx:
                val = ctx[expr]
                if isinstance(val, list):
                    return ','.join(str(v) for v in val)
                return str(val)
            return match.group(0)
        if isinstance(value, str):
            return re.sub(r'{{(.*?)}}', replace, value)
        elif isinstance(value, list):
            return [self._substitute(item, extra_context) for item in value]
        elif isinstance(value, dict):
            return {k: self._substitute(v, extra_context) for k, v in value.items()}
        return value

    def _make_request(self, method, url, headers, body, stage, retries=3):
        for attempt in range(retries + 1):
            self.session = self._get_session()
            try:
                all_headers = self.session.headers.copy()
                all_headers.update(headers)
                if body and 'Content-Type' not in all_headers:
                    all_headers['Content-Type'] = 'application/json'
                timeout = stage.get('timeout', self.timeout)
                self._throttle(retry=(attempt > 0))
                resp = self.session.request(
                    method, url, headers=all_headers, data=body,
                    timeout=timeout, allow_redirects=True
                )
                if resp.status_code in [429, 503] and attempt < retries:
                    backoff = 2 ** attempt
                    time.sleep(backoff)
                    continue
                return resp
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                return None
        return None

    def _match_stage(self, response, stage, context):
        matchers = stage.get('matchers', [])
        if not matchers:
            return True
        valid = [m for m in matchers if isinstance(m, dict)]
        if not valid:
            return False
        body_text = self._decode_response_body(response)
        if any(p in body_text.lower() for p in self.block_patterns):
            return False
        condition = stage.get('matchers-condition', 'and')
        results = []
        for matcher in valid:
            matched = self._evaluate_matcher(response, matcher, context)
            results.append(matched)
        return all(results) if condition == 'and' else any(results)

    def _evaluate_matcher(self, response, matcher, context):
        mtype = matcher.get('type', '')
        if mtype == 'status':
            expected = matcher.get('status', [])
            if isinstance(expected, int):
                expected = [expected]
            return response.status_code in expected
        elif mtype == 'word':
            words = matcher.get('words', [])
            part = matcher.get('part', 'body')
            data = self._decode_response_body(response) if part == 'body' else str(response.headers)
            negative = matcher.get('negative', False)
            found = any(w in data for w in words)
            return not found if negative else found
        elif mtype == 'regex':
            patterns = matcher.get('regex', [])
            part = matcher.get('part', 'body')
            data = self._decode_response_body(response) if part == 'body' else str(response.headers)
            negative = matcher.get('negative', False)
            found = any(re.search(p, data) for p in patterns)
            return not found if negative else found
        return False

    def _extract_from_response(self, response, extractors, context):
        extracted = {}
        if not extractors:
            return extracted
        if isinstance(extractors, dict):
            extractors = [extractors]
        for ex in extractors:
            if not isinstance(ex, dict):
                continue
            etype = ex.get('type', '')
            name = ex.get('name')
            if not name:
                continue
            if etype == 'json':
                try:
                    data = response.json()
                    for jp in ex.get('json', []):
                        if jsonpath_ng:
                            expr = jsonpath_ng.parse(jp)
                            matches = expr.find(data)
                            if matches:
                                val = [m.value for m in matches]
                                if len(val) == 1:
                                    val = val[0]
                                context[name] = val
                                extracted[name] = val
                                break
                except:
                    pass
            elif etype == 'regex':
                part = ex.get('part', 'body')
                data = self._decode_response_body(response) if part == 'body' else str(response.headers)
                for pat in ex.get('regex', []):
                    matches = re.findall(pat, data)
                    if matches:
                        val = matches[0] if len(matches) == 1 else matches
                        context[name] = val
                        extracted[name] = val
                        break
            elif etype == 'raw':
                raw_value = ex.get('value', '')
                context[name] = raw_value
                extracted[name] = raw_value
        return extracted

    def _build_evidence(self, method, url, req_headers, req_body, response):
        body_text = self._decode_response_body(response)
        return {
            'method': method,
            'url': url,
            'request_headers': dict(req_headers),
            'request_body': req_body,
            'status': response.status_code,
            'response_headers': dict(response.headers),
            'response_body': body_text,
            'response_length': len(response.content),
        }

    def _execute_request(self, stage, extra_context=None):
        method = stage.get('method', 'GET').upper()
        paths = self._substitute(stage.get('path', []), extra_context)
        if isinstance(paths, str):
            paths = [paths]
        elif not isinstance(paths, list):
            return None, None, None
        headers = self._substitute(stage.get('headers', {}), extra_context)
        body = self._substitute(stage.get('body', ''), extra_context)
        raw_body = self._substitute(stage.get('raw_body', ''), extra_context)
        req_body = raw_body or body
        if isinstance(req_body, dict):
            req_body = json.dumps(req_body)

        payloads = stage.get('payloads', {})
        if payloads:
            keys = list(payloads.keys())
            values = [self._substitute(payloads[k], extra_context) for k in keys]
            values = [v if isinstance(v, list) else [v] for v in values]
            import itertools
            for combo in itertools.product(*values):
                pctx = dict(zip(keys, combo))
                ictx = {**extra_context, **pctx} if extra_context else pctx
                full_path = self._substitute(paths[0], ictx)
                full_url = urljoin(self.base_url, full_path)
                resp = self._make_request(method, full_url, headers, req_body, stage)
                if resp and self._match_stage(resp, stage, ictx):
                    evidence = self._build_evidence(method, full_url, headers, req_body, resp)
                    return resp, evidence, ictx
            return None, None, None
        else:
            full_path = self._substitute(paths[0], extra_context) if paths else ''
            full_url = urljoin(self.base_url, full_path)
            resp = self._make_request(method, full_url, headers, req_body, stage)
            if resp and self._match_stage(resp, stage, extra_context):
                evidence = self._build_evidence(method, full_url, headers, req_body, resp)
                return resp, evidence, extra_context
            return None, None, None

    def _attempt_exploitation(self, finding, template):
        exploit_section = template.get('exploitation')
        if not exploit_section:
            return None
        method = exploit_section.get('method', 'GET')
        path_template = exploit_section.get('path', '')
        headers = exploit_section.get('headers', {})
        body_template = exploit_section.get('body', '')
        extractor = exploit_section.get('extract', {})
        ctx = {**self.context, **finding.get('extracted', {})}
        ctx.update(self.auth.auth_data)
        path = self._substitute(path_template, ctx)
        url = urljoin(self.base_url, path)
        body = self._substitute(body_template, ctx)
        headers = {k: self._substitute(v, ctx) for k, v in headers.items()}
        self._throttle()
        try:
            resp = self.session.request(method, url, headers=headers, data=body,
                                        timeout=self.timeout, allow_redirects=True)
            success = False
            output = ''
            if extractor:
                etype = extractor.get('type')
                if etype == 'regex':
                    match = re.search(extractor.get('pattern', ''), resp.text)
                    if match:
                        output = match.group(1)
                        success = True
                elif etype == 'json':
                    try:
                        data = resp.json()
                        jpath = extractor.get('path')
                        if jpath and jsonpath_ng:
                            expr = jsonpath_ng.parse(jpath)
                            matches = expr.find(data)
                            if matches:
                                output = [m.value for m in matches]
                                success = True
                    except:
                        pass
                elif etype == 'status':
                    if resp.status_code == extractor.get('expected', 200):
                        success = True
                        output = f"Status {resp.status_code}"
            else:
                if resp.status_code == 200:
                    success = True
                    output = resp.text[:500]
            return {
                'success': success,
                'request': {'method': method, 'url': url, 'headers': dict(headers), 'body': body},
                'response': {'status': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text},
                'output': output,
            }
        except:
            return None

    def _execute_template(self, template):
        template_id = template.get('id', 'unknown')
        template_name = template.get('name', template_id)
        severity = template.get('severity', 'info')
        impact = template.get('impact', 'No impact description provided.')
        chain = template.get('chain', 'No chaining information provided.')
        stages = template.get('requests', [])
        local_context = self.context.copy()
        stage_vars = {}
        for idx, stage in enumerate(stages):
            extra = {**local_context, **stage_vars}
            response, evidence, updated_ctx = self._execute_request(stage, extra)
            if not response:
                continue
            extractors = stage.get('extractors', [])
            extracted = self._extract_from_response(response, extractors, local_context)
            stage_vars.update(extracted)
            local_context.update(extracted)
            finding = {
                'template_id': template_id,
                'name': template_name,
                'severity': severity,
                'impact': impact,
                'chain': chain,
                'evidence': evidence,
                'extracted': extracted,
                'exploit': None,
            }
            if self.exploit_enabled:
                exploit_result = self._attempt_exploitation(finding, template)
                if exploit_result:
                    finding['exploit'] = exploit_result
                    if not self.quiet:
                        print(f"[EXPLOIT] {template_id} – {'SUCCESS' if exploit_result['success'] else 'FAILED'}")
            self.findings.append(finding)
            if not self.quiet:
                print(f"[VULN] {severity.upper()}: {template_name} at {evidence['url']}")
            break

    def run(self):
        if not self.skip_auth:
            if not self.quiet:
                print("[AUTH] Attempting to authenticate...")
            if not self.auth.authenticate(self.username, self.password):
                if not self.quiet:
                    print("[AUTH] Auto-authentication failed. Continuing without auth.")
            else:
                if not self.quiet:
                    print("[AUTH] Authentication successful.")
        else:
            if not self.quiet:
                print("[AUTH] Skipped (--no-auth).")

        self.load_templates()
        if not self.templates:
            if not self.quiet:
                print("[WARN] No templates loaded. Nothing to scan.")
            return {
                'url': self.raw_url,
                'base_url': self.base_url,
                'scan_id': self.scan_id,
                'findings': self.findings,
                'total_templates': 0,
            }
        if not self.quiet:
            print(f"[SCANNER] Running {len(self.templates)} templates against {self.base_url}...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._execute_template, tpl): tpl for tpl in self.templates}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if not self.quiet:
                        print(f"[ERROR] Template failed: {e}")
                        traceback.print_exc()
        return {
            'url': self.raw_url,
            'base_url': self.base_url,
            'scan_id': self.scan_id,
            'findings': self.findings,
            'total_templates': len(self.templates),
        }


def scan_target(url, quiet=False, template_dir='templates/', **kwargs):
    scanner = Scanner(
        url=url,
        quiet=quiet,
        template_dir=template_dir,
        max_workers=kwargs.get('max_workers', 10),
        proxy_file=kwargs.get('proxy_file'),
        country=kwargs.get('country'),
        rate_limit=kwargs.get('rate_limit', 0),
        delay=kwargs.get('delay', 2),
        jitter=kwargs.get('jitter', 0.5),
        exploit=kwargs.get('exploit', False),
        username=kwargs.get('username'),
        password=kwargs.get('password'),
        timeout=kwargs.get('timeout', 10),
        skip_priv=kwargs.get('skip_priv', False),
        skip_auth=kwargs.get('skip_auth', False),
    )
    return scanner.run()
