#!/usr/bin/env bash
set -euo pipefail

cd "${1:-$HOME/VulnForge}"

if [[ ! -f terminal/cli.py || ! -f engine/scanner.py || ! -f core/database.py ]]; then
  echo "[ERROR] Run this from the VulnForge project directory."
  exit 1
fi

STAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "backup_$STAMP"
cp terminal/cli.py engine/scanner.py core/database.py "backup_$STAMP/"

python3 - <<'PY'
from pathlib import Path

# terminal/cli.py
p = Path('terminal/cli.py')
s = p.read_text()
if 'from pathlib import Path' not in s:
    s = s.replace('import threading\n', 'import threading\nfrom pathlib import Path\n', 1)
s = s.replace("skip_auth=args.no_auth,", "skip_auth=(args.no_auth or ((not args.username or not args.password) and not args.auto_auth)),\n            auto_auth=args.auto_auth,", 1)
s = s.replace("parser.add_argument('-T', '--templates', default='templates/', help='Template file or directory')",
              "parser.add_argument('-T', '--templates', default=str(Path(__file__).resolve().parents[1] / 'templates'), help='Template file or directory')", 1)
s = s.replace("parser.add_argument('--exploit', action='store_true', help='Enable exploitation (default aggressive: ON)')",
              "parser.add_argument('--exploit', action='store_true', default=None, help='Enable exploitation')", 1)
s = s.replace("parser.add_argument('--full', action='store_true', help='Show full request/response (default aggressive: ON)')",
              "parser.add_argument('--full', action='store_true', default=None, help='Show full request/response')", 1)
s = s.replace("parser.add_argument('--no-auth', action='store_true', help='Skip authentication (register/login)')",
              "parser.add_argument('--no-auth', action='store_true', help='Skip authentication')\n    parser.add_argument('--auto-auth', action='store_true', help='Allow automatic account registration (off by default)')", 1)
old = '''    with ThreadPoolExecutor(max_workers=args.threads) as executor:\n        futures = {executor.submit(scan_single_target, t, args): t for t in targets}\n        for future in as_completed(futures):\n            try:\n                results.append(future.result())\n            except Exception as e:\n                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")\n'''
new = '''    executor = ThreadPoolExecutor(max_workers=max(1, args.threads))\n    futures = {executor.submit(scan_single_target, t, args): t for t in targets}\n    interrupted = False\n    try:\n        for future in as_completed(futures):\n            try:\n                results.append(future.result())\n            except KeyboardInterrupt:\n                interrupted = True\n                print(f"\\n{Fore.YELLOW}[!] Scan interrupted. Cancelling pending tasks...{Style.RESET_ALL}")\n                for pending in futures:\n                    pending.cancel()\n                break\n            except Exception as e:\n                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")\n    finally:\n        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)\n'''
if old in s:
    s = s.replace(old, new, 1)
s = s.replace('spinner_thread.join()', 'spinner_thread.join(timeout=1)', 1)
s = s.replace('''    if not args.quiet:\n        print(f"\\n{Fore.CYAN}[+] Scan completed in {elapsed:.2f}s, {total} findings{Style.RESET_ALL}")''',
'''    if not args.quiet:\n        label = 'Scan interrupted' if interrupted else 'Scan completed'\n        print(f"\\n{Fore.CYAN}[+] {label} in {elapsed:.2f}s, {total} findings{Style.RESET_ALL}")''', 1)
p.write_text(s)

# engine/scanner.py
p = Path('engine/scanner.py')
s = p.read_text()
s = s.replace('def __init__(self, session, base_url, quiet=False):\n        self.session = session\n        self.base_url = base_url\n        self.quiet = quiet\n',
'''def __init__(self, session, base_url, quiet=False, timeout=10):\n        self.session = session\n        self.base_url = base_url\n        self.quiet = quiet\n        self.timeout = max(1, int(timeout))\n''', 1)
s = s.replace('self.session.post(url, json=data)', 'self.session.post(url, json=data, timeout=self.timeout)', 1)
s = s.replace('self.session.post(url, data=data)', 'self.session.post(url, data=data, timeout=self.timeout)', 1)
s = s.replace("self.session.post(url, json={'email': username, 'password': password})", "self.session.post(url, json={'email': username, 'password': password}, timeout=self.timeout)", 1)
s = s.replace("self.session.post(url, data={'username': username, 'password': password})", "self.session.post(url, data={'username': username, 'password': password}, timeout=self.timeout)", 1)
s = s.replace('''    def authenticate(self, username=None, password=None):\n        if not username:\n            if self.register():\n                return self.login()\n        else:\n            self.auth_data['username'] = username\n            self.auth_data['password'] = password\n            return self.login()\n        return False\n''', '''    def authenticate(self, username=None, password=None, auto_register=False):\n        # Never create an account on an arbitrary target unless explicitly requested.\n        if username and password:\n            self.auth_data['username'] = username\n            self.auth_data['password'] = password\n            return self.login()\n        if auto_register and self.register():\n            return self.login()\n        return False\n''', 1)
s = s.replace('skip_priv=False, skip_auth=False):', 'skip_priv=False, skip_auth=False, auto_auth=False):', 1)
s = s.replace('self.skip_auth = skip_auth\n', 'self.skip_auth = skip_auth\n        self.auto_auth = auto_auth\n', 1)
s = s.replace('self.auth = AuthManager(self.session, self.base_url, self.quiet)', 'self.auth = AuthManager(self.session, self.base_url, self.quiet, self.timeout)', 1)
s = s.replace('self.auth.authenticate(self.username, self.password)', 'self.auth.authenticate(self.username, self.password, auto_register=self.auto_auth)', 1)
s = s.replace('''        else:\n            if not self.quiet:\n                print("[AUTH] Skipped (--no-auth).")\n''', '''        else:\n            if not self.quiet:\n                if not (self.username and self.password):\n                    reason = "no credentials supplied"\n                else:\n                    reason = "--no-auth"\n                print(f"[AUTH] Skipped ({reason}).")\n''', 1)
s = s.replace("skip_auth=kwargs.get('skip_auth', False),\n", "skip_auth=kwargs.get('skip_auth', False),\n        auto_auth=kwargs.get('auto_auth', False),\n", 1)
p.write_text(s)

# core/database.py
p = Path('core/database.py')
s = p.read_text()
if 'from pathlib import Path' not in s:
    s = s.replace('import os\n', 'import os\nfrom pathlib import Path\n', 1)
s = s.replace("DB_PATH = 'vulnforge.db'", "PROJECT_ROOT = Path(__file__).resolve().parents[1]\nDB_PATH = str(PROJECT_ROOT / 'vulnforge.db')", 1)
old = """                columns_to_add = [\n                    ('confirmed', 'BOOLEAN DEFAULT 0'),\n                    ('exploit_attempted', 'BOOLEAN DEFAULT 0'),\n                    ('exploit_success', 'BOOLEAN DEFAULT 0'),\n                    ('confidence', 'REAL DEFAULT 0.0'),\n                    ('cwe', 'TEXT'),\n                    ('owasp', 'TEXT'),\n                    ('remediation', 'TEXT'),\n                    ('created_at', 'TEXT'),  # no default\n                ]\n"""
new = """                columns_to_add = [\n                    ('template_id', 'TEXT'),\n                    ('name', \"TEXT DEFAULT ''\"),\n                    ('impact', 'TEXT'),\n                    ('chain', 'TEXT'),\n                    ('extracted', 'TEXT'),\n                    ('confirmed', 'BOOLEAN DEFAULT 0'),\n                    ('exploit_attempted', 'BOOLEAN DEFAULT 0'),\n                    ('exploit_success', 'BOOLEAN DEFAULT 0'),\n                    ('confidence', 'REAL DEFAULT 0.0'),\n                    ('cwe', 'TEXT'),\n                    ('owasp', 'TEXT'),\n                    ('remediation', 'TEXT'),\n                    ('created_at', 'TEXT'),\n                ]\n"""
if old in s:
    s = s.replace(old, new, 1)
needle = """                for col_name, col_type in columns_to_add:\n                    if not column_exists(cursor, 'findings', col_name):\n                        cursor.execute(f'ALTER TABLE findings ADD COLUMN {col_name} {col_type}')\n                        logger.info(f\"Added column '{col_name}' to findings table.\")\n\n            # --- Migrate fingerprints table ---\n"""
replacement = """                for col_name, col_type in columns_to_add:\n                    if not column_exists(cursor, 'findings', col_name):\n                        cursor.execute(f'ALTER TABLE findings ADD COLUMN {col_name} {col_type}')\n                        logger.info(f\"Added column '{col_name}' to findings table.\")\n\n                if column_exists(cursor, 'findings', 'title') and column_exists(cursor, 'findings', 'name'):\n                    cursor.execute(\"UPDATE findings SET name = COALESCE(NULLIF(name, ''), title) WHERE title IS NOT NULL\")\n                if column_exists(cursor, 'findings', 'kind') and column_exists(cursor, 'findings', 'template_id'):\n                    cursor.execute(\"UPDATE findings SET template_id = COALESCE(template_id, kind) WHERE kind IS NOT NULL\")\n\n            # --- Migrate fingerprints table ---\n"""
if needle in s:
    s = s.replace(needle, replacement, 1)
p.write_text(s)
PY

python3 -m py_compile terminal/cli.py engine/scanner.py core/database.py

echo "[OK] VulnForge fixed. Backup: backup_$STAMP"
echo "[OK] Test with: VulnForge -u http://127.0.0.1:8000 --no-fingerprint --no-auth --no-exploit --no-full --no-aggressive"
