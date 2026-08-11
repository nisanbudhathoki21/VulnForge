🛡️ VulnForge v2.0
Next-Generation Web Security Assessment Framework

Dynamic Spider · Live Penetration Testing Workstation · Zero False-Positive Engine

An evidence-first vulnerability scanner that replaces noisy status-code checks with a 5-stage Verification State Machine — eliminating soft-404 false alarms, exploring modern SPAs and APIs dynamically, and providing an interactive dashboard with an integrated Burp Suite–style Live Repeater.
🧰 Tech Stack

Core Engine: Python 3.9+, Requests, AsyncIO (concurrency), Regex-based fingerprinting

Storage & Persistence: SQLite (WAL mode, concurrent writes)

Dashboard & Real-Time Interface: Flask, Streamlit, Server-Sent Events (live streaming), HTML5, CSS3, JavaScript

Reporting: ReportLab (PDF engine), Markdown export, Burp Suite XML export

Tooling & Environment: Kali Linux, Git, GitHub, CLI
📑 Table of Contents

    System Architecture & Workflow
    How the Verification State Machine Works
    Key Features
    System Requirements
    Step-by-Step Installation Guide
    How to Run VulnForge
        1. Interactive Web Dashboard & Live Repeater
        2. Command-Line (CLI) Safe Mode
        3. Working with Isolated Project Databases
    CLI Flags Reference
    Verification Oracles by Vulnerability Class
    Troubleshooting & Common Errors
    Exporting Reports
    Legal & Ethical Disclaimer

🔬 How the Verification State Machine Works

Traditional security scanners flag issues whenever an endpoint returns HTTP 200. In modern single-page applications (React, Angular, Next.js), almost every URL returns 200 OK with an HTML catch-all template, flooding scan reports with false leads.

VulnForge implements a 5-stage verification state machine:

    [Candidate Endpoint]
             │
             ▼
      ┌─────────────┐
      │ DISCOVERED  │  Spider maps route, parameters, and HTTP method.
      └──────┬──────┘
             │
             ▼
      ┌─────────────┐
      │   CONTROL   │  Sends negative/baseline payload to record normal state.
      └──────┬──────┘
             │
             ▼
      ┌─────────────┐
      │  MUTATION   │  Sends targeted security probe across the parameter.
      └──────┬──────┘
             │
             ▼
      ┌─────────────┐
      │   IMPACT    │  Differential analysis: Did state, syntax, or data change?
      └──────┬──────┘
             │
        ┌────┴──────────────────────────┐
        │                               │
  [PASSED ORACLE]                [FAILED ORACLE]
        │                               │
        ▼                               ▼
┌────────────────────────────┐  ┌────────────────────────────┐
│      100% CONFIRMED        │  │    DISCARDED FALSE LEAD     │
│ • True positive confirmed  │  │ • Soft-404 HTML catch-all   │
│ • Full wire proof recorded │  │ • Filtered from scan report │
│ • Control vs Mutation diff │  │ • Zero noise in database    │
└────────────────────────────┘  └────────────────────────────┘

✨ Key Features
Feature 	Description
🎯 Zero False-Positive Engine 	Soft-404 profiler automatically discards SPA fallback pages.
🧾 Burp Suite Wire Evidence 	Every finding records the full raw HTTP request and response wire packets.
🕷️ Dynamic Web Spider 	Discovers hidden endpoints, query parameters, and HTML forms across modern web apps.
🖥️ Interactive Live Workstation 	Web dashboard with real-time SSE scanning console and findings modal.
🔁 Burp Suite Live Repeater 	Edit and send custom raw HTTP requests on the fly with millisecond latency tracking.
🐢 Safe-Mode Production Pacing 	Adaptive token-bucket rate limiter with automatic exponential backoff on HTTP 429 / 503.
🗄️ Isolated Database Support 	Run separate audits for different clients using the --db flag or VULNFORGE_DB_PATH.
📤 Multi-Format Reporting 	Instant export to Executive PDF Reports (ReportLab), Markdown, JSON, and Burp Suite XML.
💻 System Requirements
Requirement 	Details
Operating System 	Linux (Kali, Ubuntu, Debian), macOS, or Windows (WSL2)
Python Version 	Python 3.9 or newer
Network Access 	Outbound HTTP/HTTPS access to target applications
📦 Step-by-Step Installation Guide
Step 1 — Clone the Repository

git clone https://github.com/nisanbudhathoki21/VulnForge.git
cd VulnForge

Step 2 — Set Up a Python Virtual Environment

python3 -m venv .venv
source .venv/bin/activate

Step 3 — Install Required Dependencies

pip install -r requirements.txt

Step 4 — Install the Global CLI Command

pip install -e .
chmod +x run.sh cli.py

⚡ How to Run VulnForge
1. Interactive Web Dashboard & Live Repeater

Start the live web workstation:

./run.sh

Open your browser and navigate to:

http://localhost:8000

What you can do in the Dashboard:

    Start Scans — enter a target URL in the top search bar and watch live progress in the terminal stream.
    Inspect Wire Packets — click on any finding to view the exact raw HTTP request and response.
    Live Repeater — switch to the Live Burp Repeater tab to write, modify, and dispatch custom HTTP requests manually.
    Export Reports — download one-click PDF, Markdown, or Burp XML files.

2. Command-Line (CLI) Safe Mode

For terminal assessments or bug bounty programs, use safe rate-limiting:

# Safe scan pacing (5 req/sec) with automated PDF and Markdown exports
VulnForge -u https://example.com --rate-limit 5.0 -t 8 --timeout 5.0 --pdf report.pdf --markdown report.md

3. Working with Isolated Project Databases

Store scan data in separate database files for different clients, programs, or dates.

Option A — Using the CLI --db flag

# Project Alpha audit saved to client_a.db
VulnForge --db client_a.db -u https://target-a.com -t 10

# Project Beta audit saved to client_b.db
VulnForge --db client_b.db -u https://target-b.com -t 10

Option B — Running the Web Dashboard on a Specific Database

VULNFORGE_DB_PATH=client_a.db python3 server.py

Open http://localhost:8000 to view findings and stats for that specific database.
🛠️ CLI Flags Reference
Flag 	Description 	Default 	Example
-u, --url 	Required. Target URL to assess 	None 	-u https://target.com
--db 	Custom SQLite database file path 	vulnforge.db 	--db audit.db
--rate-limit 	Maximum requests per second (Safe Mode) 	8.0 	--rate-limit 5.0
-t, --threads 	Concurrent worker threads 	10 	-t 15
--timeout 	HTTP request timeout in seconds 	5.0 	--timeout 6.0
--whitelist 	Additional subdomains strictly in scope 	None 	--whitelist api.target.com
--pdf 	Save findings into a formal PDF report 	None 	--pdf audit.pdf
--markdown 	Save findings into a Markdown file 	None 	--markdown audit.md
🎯 Verification Oracles by Vulnerability Class
Vulnerability Class 	Control Test (Baseline) 	Mutation Test (Probe) 	Impact / Verification Oracle
Mass Assignment 	Create standard user: {"email", "pass"} → returns standard role. 	Submit {"email", "pass", "role": "admin"}. 	Server response is JSON (!= text/html) and returned object contains role == "admin".
Sensitive Configs (.env) 	Request random canary /.env_canary_404. 	Request /.env. 	Response is NOT text/html, differs from canary 404, and matches key assignments (DB_PASSWORD=...).
Git Metadata (.git/HEAD) 	Request canary /.git_canary_404. 	Request /.git/HEAD. 	Response body starts with ref: refs/heads/ or matches a 40-character hexadecimal SHA-1 string.
SQL Injection 	Base query parameter ?id=1. 	Query with injection quote ?id=1'. 	Response body reflects raw database syntax error (SQLITE_ERROR, mysql_, ORA-).
Security Headers 	Baseline root probe GET /. 	Header inspection. 	Verified omission of CSP, Strict-Transport-Security, or X-Frame-Options clickjacking headers.
Open Redirect 	Probe ?redirect=https://evil.com. 	Status and Header check. 	Response returns 301/302/307 and Location header points to external domain.
🔧 Troubleshooting & Common Errors

Error 1 — unrecognized arguments: --pdf test_report.pdf

    Cause: Your environment is executing an older cached version of cli.py.
    Fix: Reinstall the package entry point: pip install -e .

Error 2 — ModuleNotFoundError: No module named 'engine.reporter'

    Cause: Missing module file or running from outside the project root directory.
    Fix: Ensure you are in the VulnForge root folder and run pip install -r requirements.txt.

Error 3 — python3: can't open file 'seed.py': [Errno 2] No such file or directory

    Cause: Running ./run.sh from a parent folder instead of inside the repository.
    Fix: cd ~/VulnForge && ./run.sh

Error 4 — Scanner finishes in 1 second with 0 requests

    Cause: The target domain is unreachable or blocked by an invalid scope whitelist.
    Fix: Ensure the URL starts with http:// or https:// and test connectivity with curl -I <URL>.

📄 Exporting Reports
Format 	Purpose
Executive PDF Report 	Risk severity matrices, CVSS v3.1 metrics, reproduction evidence, and remediation steps for engineering teams.
Markdown Summary 	Clean format for bug bounty submissions or issue trackers.
Burp Suite XML 	Import scan findings directly into Burp Suite Professional / Community via Target → Site Map.
⚖️ Legal & Ethical Disclaimer

    VulnForge is designed exclusively for authorized penetration testing, security research, and educational purposes.

    Scanning targets without prior explicit mutual consent is illegal. The developers assume no liability for misuse, unauthorized testing, or damage caused by this program. Always adhere to program rules of engagement and responsible disclosure guidelines.

Built with 🛡️ by Nisan Budhathoki
