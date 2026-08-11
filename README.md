# 🛡️ VulnForge v2.0.0

## Next-Generation Web Security Assessment Framework

**Dynamic Spider · Live Penetration Testing Workstation · Evidence-First Verification Engine**

VulnForge is an evidence-first web security assessment framework designed for **authorized penetration testing, security research, and educational use**.

Version 2.0 introduces a verification-driven architecture that moves beyond simple status-code heuristics by using a **5-stage Verification State Machine**, dynamic endpoint discovery, differential response analysis, raw HTTP evidence collection, safe traffic pacing, isolated SQLite databases, and an interactive web workstation.

> **Important:** A vulnerability should not be considered confirmed merely because an endpoint returns `HTTP 200`. VulnForge attempts to establish behavioral evidence before recording a finding as verified.

---

## 📋 Table of Contents

* [What's New in v2.0.0](#-whats-new-in-v200)
* [Architecture](#-architecture)
* [Verification State Machine](#-verification-state-machine)
* [Key Features](#-key-features)
* [Tech Stack](#-tech-stack)
* [System Requirements](#-system-requirements)
* [Installation](#-installation)
* [Running VulnForge](#-running-vulnforge)

  * [Web Workstation](#1-web-workstation--live-repeater)
  * [CLI Safe Mode](#2-command-line-cli-safe-mode)
  * [Isolated Databases](#3-isolated-project-databases)
* [CLI Reference](#-cli-reference)
* [Verification Oracles](#-verification-oracles)
* [Sample Output](#-sample-output)
* [Troubleshooting](#-troubleshooting)
* [Reporting](#-reporting)
* [Project Structure](#-project-structure)
* [Security and Ethical Use](#-security-and-ethical-use)
* [License](#-license)

---

## 🚀 What's New in v2.0.0

VulnForge v2.0.0 represents a major architectural evolution from a primarily heuristic scanner into an **evidence-first, verification-driven web security assessment workstation**.

### Major changes

| Area                    | v1.x                       | v2.0.0                                       |
| ----------------------- | -------------------------- | -------------------------------------------- |
| Verification            | Status-code heuristics     | 5-stage verification state machine           |
| False-positive handling | Limited                    | Baseline and soft-404 differential analysis  |
| Endpoint discovery      | Static probes              | Dynamic spider and route discovery           |
| HTTP evidence           | Basic response information | Raw request/response evidence                |
| Interactive testing     | CLI-oriented               | Web workstation + Live Repeater              |
| Rate control            | Limited                    | Token-bucket pacing and backoff              |
| Database                | Shared/default database    | Project-specific SQLite databases            |
| Reporting               | Basic output               | PDF, Markdown, JSON, and Burp XML            |
| Scope protection        | Limited                    | Scope validation and protected-path handling |

---

# 🏗️ Architecture

The v2.0 pipeline is organized around six major components:

```text
                         ┌──────────────────────────┐
                         │      TARGET URL INPUT    │
                         │ CLI / Web Workstation    │
                         └────────────┬─────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. SCOPE GUARD & BASELINE PROFILER                             │
│                                                                 │
│ • Validates target scope                                       │
│ • Establishes baseline behavior                                │
│ • Detects soft-404 / SPA fallback responses                    │
│ • Applies protected-path handling                              │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. DYNAMIC WEB SPIDER & ROUTE DISCOVERY                        │
│                                                                 │
│ • HTML links                                                  │
│ • Forms                                                       │
│ • Script resources                                             │
│ • Query parameters                                             │
│ • Frontend-discovered routes                                  │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. REQUEST PACING & CONNECTION MANAGEMENT                      │
│                                                                 │
│ • Configurable request rate                                   │
│ • Concurrent workers                                          │
│ • Timeout handling                                            │
│ • Backoff for rate-limit responses                             │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. VERIFICATION STATE MACHINE                                 │
│                                                                 │
│ DISCOVERED → CONTROL → MUTATION → IMPACT → VERDICT             │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                 ┌──────────────┴──────────────┐
                 │                             │
                 ▼                             ▼
      ┌─────────────────────┐       ┌────────────────────────┐
      │ VERIFIED FINDING    │       │ DISCARDED LEAD         │
      │                     │       │                        │
      │ • Evidence stored   │       │ • Baseline matched     │
      │ • Request recorded  │       │ • Soft-404 detected    │
      │ • Response recorded │       │ • Oracle failed        │
      └──────────┬──────────┘       └────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. PERSISTENCE & REPORTING                                     │
│                                                                 │
│ SQLite • JSON • Markdown • PDF • Burp XML                      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. WEB WORKSTATION & TELEMETRY                                │
│                                                                 │
│ • Live scan output                                             │
│ • Findings                                                     │
│ • Raw HTTP evidence                                           │
│ • Live Repeater                                               │
└─────────────────────────────────────────────────────────────────┘
```

---

# 🔬 Verification State Machine

Traditional scanners can generate large numbers of false positives when applications return the same `HTTP 200 OK` response for both valid and nonexistent routes.

This is particularly common with modern:

* React applications
* Angular applications
* Next.js applications
* SPA routers
* CDN configurations
* Custom error handlers

VulnForge therefore uses a staged verification process.

```text
┌──────────────┐
│ DISCOVERED   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ CONTROL      │
│ Baseline     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ MUTATION     │
│ Security     │
│ Probe        │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ IMPACT       │
│ Differential │
│ Analysis     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ VERDICT      │
└──────┬───────┘
       │
   ┌───┴────┐
   │        │
   ▼        ▼
PASS       FAIL
   │        │
   ▼        ▼
VERIFIED   DISCARDED
```

### 1. DISCOVERED

The scanner identifies:

* Endpoint
* HTTP method
* Parameters
* Forms
* Candidate routes

### 2. CONTROL

A baseline request establishes normal application behavior.

This is important because the scanner needs something to compare the security probe against.

### 3. MUTATION

A targeted security probe modifies the relevant request parameter or resource.

### 4. IMPACT

The control and mutation responses are compared.

Depending on the vulnerability class, VulnForge can examine:

* HTTP status
* Response headers
* Response body
* Content type
* Response length
* Response signatures
* Database error indicators
* Redirect destinations
* Application state indicators

### 5. VERDICT

The result is classified according to the verification logic.

A failed oracle should be discarded rather than automatically promoted into a confirmed vulnerability.

---

# ✨ Key Features

| Feature                        | Description                                                                        |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| 🎯 Evidence-First Verification | Uses control/mutation comparisons instead of relying solely on status codes.       |
| 🧹 Soft-404 Detection          | Attempts to identify SPA and catch-all responses before treating them as findings. |
| 🧾 Raw HTTP Evidence           | Findings can retain request and response evidence for reproduction.                |
| 🕷️ Dynamic Web Spider         | Discovers links, forms, routes, and parameters.                                    |
| 🖥️ Web Workstation            | Provides an interactive interface for scans and findings.                          |
| 🔁 Live Repeater               | Allows authorized manual HTTP request testing from the workstation.                |
| 🐢 Safe Request Pacing         | Configurable request rate and backoff behavior.                                    |
| 🗄️ Project Databases          | Separate SQLite databases can be used for separate assessments.                    |
| 📊 Reporting                   | Supports PDF, Markdown, JSON, and Burp-compatible XML exports.                     |
| 🔍 Differential Analysis       | Compares baseline and mutated responses.                                           |
| 🛡️ Scope Controls             | Helps prevent accidental requests outside the intended target scope.               |

---

# 🧰 Tech Stack

| Component     | Technology                                |
| ------------- | ----------------------------------------- |
| Language      | Python 3.9+                               |
| HTTP          | Requests / HTTP client components         |
| Concurrency   | AsyncIO / worker-based concurrency        |
| Database      | SQLite                                    |
| Database Mode | WAL where supported                       |
| Web Interface | Flask / HTML / CSS / JavaScript           |
| Streaming     | Server-Sent Events                        |
| Reporting     | ReportLab / Markdown / JSON / XML         |
| Environment   | Linux / Kali Linux / macOS / Windows WSL2 |

---

# 💻 System Requirements

| Requirement         | Minimum                              |
| ------------------- | ------------------------------------ |
| Operating System    | Linux, macOS, or Windows WSL2        |
| Python              | 3.9+                                 |
| RAM                 | 2 GB+ recommended                    |
| Network             | Outbound HTTP/HTTPS access           |
| Git                 | Required for source installation     |
| pip                 | Required for dependency installation |
| Virtual Environment | Recommended                          |

---

# 📦 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/nisanbudhathoki21/VulnForge.git
cd VulnForge
```

## 2. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows WSL2

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 4. Install VulnForge

```bash
pip install -e .
```

## 5. Make the Launcher Executable

```bash
chmod +x run.sh
```

---

# ⚡ Running VulnForge

## 1. Web Workstation & Live Repeater

Start the web workstation:

```bash
./run.sh
```

Then open:

```text
http://localhost:8000
```

The workstation can provide:

* Live scan telemetry
* Scan status
* Findings
* HTTP evidence
* Request/response inspection
* Live Repeater functionality
* Report exports

---

## 2. Command-Line (CLI) Safe Mode

Example:

```bash
VulnForge \
  -u https://example.com \
  --rate-limit 5.0 \
  -t 8 \
  --timeout 5.0 \
  --pdf report.pdf \
  --markdown report.md
```

Use this only against systems where you have explicit authorization to test.

---

## 3. Isolated Project Databases

VulnForge can use separate SQLite database files for separate assessments.

### Project Alpha

```bash
VulnForge \
  --db client_a.db \
  -u https://target-a.example \
  -t 10
```

### Project Beta

```bash
VulnForge \
  --db client_b.db \
  -u https://target-b.example \
  -t 10
```

### Start the dashboard with a specific database

```bash
VULNFORGE_DB_PATH=client_a.db python3 server.py
```

Then open:

```text
http://localhost:8000
```

---

# 🛠️ CLI Reference

| Flag              | Description                  |        Default | Example                      |
| ----------------- | ---------------------------- | -------------: | ---------------------------- |
| `-u`, `--url`     | Target URL to assess         |           None | `-u https://target.com`      |
| `--db`            | SQLite database path         | `vulnforge.db` | `--db audit.db`              |
| `--rate-limit`    | Maximum request rate         |          `8.0` | `--rate-limit 5.0`           |
| `-t`, `--threads` | Concurrent workers           |           `10` | `-t 15`                      |
| `--timeout`       | HTTP timeout in seconds      |          `5.0` | `--timeout 6.0`              |
| `--whitelist`     | Additional allowed subdomain |           None | `--whitelist api.target.com` |
| `--pdf`           | Export PDF report            |           None | `--pdf audit.pdf`            |
| `--markdown`      | Export Markdown report       |           None | `--markdown audit.md`        |

> **Note:** The exact available flags are determined by the installed CLI version. Run `VulnForge --help` to verify the current interface.

---

# 🎯 Verification Oracles

Verification logic depends on the vulnerability class.

| Vulnerability Class     | Control / Baseline                        | Mutation / Probe                       | Verification Signal                                                                    |
| ----------------------- | ----------------------------------------- | -------------------------------------- | -------------------------------------------------------------------------------------- |
| Mass Assignment         | Standard request without privileged field | Add a privileged field                 | Server-side state demonstrates unauthorized assignment                                 |
| Sensitive Configuration | Random nonexistent canary                 | Request sensitive configuration path   | Response differs materially from baseline and matches expected configuration structure |
| Git Metadata            | Random nonexistent Git path               | Request `.git/HEAD`                    | Git reference content or equivalent repository metadata is returned                    |
| SQL Injection           | Normal parameter value                    | Controlled syntax mutation             | Database-specific error or stronger differential evidence                              |
| Security Headers        | Baseline response                         | Inspect response headers               | Expected security header is absent                                                     |
| Open Redirect           | Normal navigation behavior                | Controlled external redirect parameter | Server redirects to an external destination                                            |

### Important

Not every oracle can be considered universally deterministic.

For example, a missing security header is a valid configuration observation, but it does **not automatically mean the application is exploitable**.

Similarly, a SQL error message is evidence of possible injection behavior, but stronger verification may be required depending on the application.

VulnForge should therefore treat its verification logic as **evidence collection**, not as a guarantee that every finding is exploitable in every environment.

---

# 📄 Sample Output

```text
=================================================================
                  VULNFORGE SCAN SUMMARY
=================================================================

Target                 : http://127.0.0.1:3000
Scan Status            : COMPLETED
Duration               : 4.85s
Total HTTP Requests    : 106
Total Findings         : 3

-----------------------------------------------------------------

[+] VERIFIED FINDINGS

[CRITICAL] Mass Assignment
Endpoint     : http://127.0.0.1:3000/api/users
Parameter    : role
Status       : VERIFIED
CVSS v3.1    : 9.8
CWE          : CWE-915

Evidence:
Control request created a standard user.
Mutation request included the privileged role field.
The resulting server-side state reflected the unauthorized value.

-----------------------------------------------------------------

[HIGH] SQL Injection
Endpoint     : http://127.0.0.1:3000/rest/products/search
Parameter    : q
Status       : VERIFIED
CWE          : CWE-89

Evidence:
Control and mutation responses differed.
The mutation response contained a database-specific error signature.

-----------------------------------------------------------------

[LOW] Missing Security Header
Endpoint     : http://127.0.0.1:3000/
Header       : Content-Security-Policy
Status       : VERIFIED

Evidence:
Response headers were inspected and the expected header was absent.

-----------------------------------------------------------------

Reports:
PDF      : test_report.pdf
Markdown : test_report.md
JSON     : scan.json
XML      : burp.xml

VulnForge assessment completed.
```

---

# 🔧 Troubleshooting

## Error: `unrecognized arguments: --pdf`

Check which executable is being used:

```bash
which VulnForge
```

Then inspect the CLI:

```bash
VulnForge --help
```

If the editable installation is stale:

```bash
pip install -e .
```

You can also check:

```bash
python -m pip show VulnForge
```

---

## Error: `ModuleNotFoundError`

Make sure the virtual environment is active:

```bash
source .venv/bin/activate
```

Then reinstall dependencies:

```bash
pip install -r requirements.txt
pip install -e .
```

Verify that you are running from the repository root:

```bash
pwd
ls
```

---

## Error: `python3: can't open file 'seed.py'`

Run VulnForge from the repository root:

```bash
cd ~/VulnForge
./run.sh
```

If your repository is located elsewhere, use its actual path.

---

## Scanner finishes quickly with zero requests

First verify connectivity:

```bash
curl -I https://example.com
```

Then verify the CLI configuration:

```bash
VulnForge --help
```

Also check:

* Target URL
* Scope configuration
* Network connectivity
* DNS resolution
* Proxy settings
* TLS problems
* Request timeout

---

# 📊 Reporting

VulnForge supports multiple output formats.

| Format   | Purpose                                              |
| -------- | ---------------------------------------------------- |
| PDF      | Formal security assessment reports                   |
| Markdown | Human-readable findings and bug bounty documentation |
| JSON     | Programmatic processing and integration              |
| Burp XML | Importing compatible findings into Burp Suite        |

Example:

```bash
VulnForge \
  -u https://example.com \
  --pdf audit.pdf \
  --markdown audit.md
```

---

# 📁 Project Structure

A simplified v2 architecture:

```text
VulnForge/
├── ai/
├── config/
├── core/
├── correlation/
├── engine/
│   ├── baseline.py
│   ├── crawler.py
│   ├── discovery.py
│   ├── endpoint_pipeline.py
│   ├── repeater.py
│   ├── reporter.py
│   ├── requester.py
│   ├── scanner.py
│   ├── verifier.py
│   └── verifier_engine.py
├── extractor/
├── httpclient/
├── matcher/
├── report/
├── reports/
├── risk/
├── static/
├── templates/
├── terminal/
├── tests/
├── utils/
├── database.py
├── cli.py
├── main.py
├── server.py
├── setup.py
├── requirements.txt
└── run.sh
```

---

# 🔐 Security and Ethical Use

VulnForge is intended for:

* Authorized penetration testing
* Bug bounty programs
* Security research
* Security education
* Testing applications you own or have explicit permission to assess

Do **not** scan systems without authorization.

Before running an assessment, verify:

1. The target is explicitly in scope.
2. Automated scanning is permitted.
3. The request rate complies with the program's rules.
4. Destructive actions are prohibited unless explicitly authorized.
5. Sensitive information discovered during testing is handled responsibly.

The existence of a technical capability in VulnForge does not grant permission to use it against a target.

---

# ⚖️ Legal Disclaimer

VulnForge is provided for authorized security testing, research, and educational purposes.

Unauthorized vulnerability scanning or penetration testing may violate applicable laws, contracts, or program rules.

The developer assumes no responsibility for misuse of the software.

Always follow the target's rules of engagement, authorization requirements, rate limits, and responsible disclosure policies.

---

# 👨‍💻 Author

**Nisan Budhathoki**

Built with 🛡️ for security research, authorized testing, and education.

---

# 📜 License

See the repository license file for the applicable terms.
