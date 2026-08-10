# VulnForge

**A YAML-driven web application security testing framework for repeatable vulnerability detection, evidence collection, and scan analysis.**

VulnForge is a Python-based security research project that provides a template-driven approach to testing web applications and APIs.

The project was built around a simple problem: individual security checks are often performed manually, while the evidence, request history, findings, and results are difficult to reproduce and compare across scans.

VulnForge addresses this by separating the scanning process into several components:

* YAML templates define security checks.
* The scanner executes those checks against an authorized target.
* HTTP responses are evaluated using matchers and extraction logic.
* Matching results are converted into findings.
* Findings and scan metadata are stored in SQLite.
* The CLI provides direct access to scanning and scan results.
* The dashboard provides a visual interface for reviewing stored scan data.
* Optional reporting and AI-assisted analysis can operate on the collected results.

> **Important:** VulnForge is intended only for authorized security testing.
> Test systems you own, intentionally vulnerable applications, or targets for which you have explicit permission.

---

## 1. Project Overview

VulnForge is not intended to replace general-purpose scanners with a collection of hard-coded vulnerability checks.

Instead, vulnerability detection is represented as data-driven YAML templates.

A template describes the request or sequence of requests that should be performed, the conditions that indicate an interesting response, and the information that should be extracted or recorded.

This makes the scanner extensible without requiring a new Python implementation for every individual detection rule.

The general execution model is:

```text
Target
   │
   ▼
Scanner
   │
   ▼
Load YAML Templates
   │
   ▼
Render Request
   │
   ▼
Send HTTP Request
   │
   ▼
Receive Response
   │
   ├───────────────┐
   ▼               ▼
Matchers       Extractors
   │               │
   └───────┬───────┘
           ▼
      Detection Result
           │
           ▼
       Finding
           │
           ├───────────────┐
           ▼               ▼
      SQLite Database    Reporting
           │
           ▼
       Dashboard
```

The important design principle is that the **scanner, database, and dashboard are connected parts of the same workflow** rather than independent demonstration components.

---

# 2. Objectives

The main objectives of VulnForge are:

1. Provide a reusable framework for web vulnerability testing.
2. Move vulnerability checks from hard-coded logic into YAML templates.
3. Support repeatable HTTP security tests.
4. Preserve scan history and findings using SQLite.
5. Maintain evidence associated with individual findings.
6. Provide both command-line and visual interfaces.
7. Allow new detection templates to be added without modifying the scanner core.
8. Provide a foundation for security research and academic experimentation.

The project is particularly useful for studying how vulnerability scanners are structured internally.

---

# 3. Why YAML Templates?

A conventional scanner can implement every vulnerability check directly inside application code.

That approach quickly becomes difficult to maintain.

For example:

```text
scanner.py
 ├── SQL injection logic
 ├── XSS logic
 ├── IDOR logic
 ├── SSRF logic
 ├── CORS logic
 ├── CSRF logic
 └── ...
```

Adding or modifying a vulnerability then requires changes to the scanner implementation.

VulnForge separates the **scanner engine** from the **detection definition**:

```text
Scanner Engine
      │
      ├── HTTP execution
      ├── rendering
      ├── matching
      ├── extraction
      └── finding creation
              ▲
              │
        YAML Template
              │
      ┌───────┴────────┐
      │ detection rule │
      │ request data   │
      │ matchers       │
      │ extractors     │
      └────────────────┘
```

This makes the template collection independently extensible.

---

# 4. Architecture

The current project is organized around several major components.

```text
                         ┌─────────────────────┐
                         │      CLI / Main     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Scanner Engine    │
                         │  engine/scanner.py  │
                         └──────────┬──────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  │                 │                 │
                  ▼                 ▼                 ▼
           YAML Templates       HTTP Layer       Recon Components
                  │                 │                 │
                  ▼                 ▼                 ▼
           Template Runtime     Responses       Target Information
                  │                 │
                  └────────┬────────┘
                           ▼
                    Match / Extract
                           │
                           ▼
                       Findings
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
        core/database.py       core/report.py
                │                     │
                ▼                     ▼
             SQLite              Reports / Analysis
                │
                ▼
       terminal/dashboard.py
                │
                ▼
          Visual Dashboard
```

---

# 5. Repository Structure

The repository is divided according to responsibility.

```text
VulnForge/
│
├── core/
│   ├── database.py
│   └── report.py
│
├── engine/
│   ├── scanner.py
│   └── recon/
│       ├── __init__.py
│       ├── crawler.py
│       ├── models.py
│       ├── parser.py
│       └── scope.py
│
├── templates/
│   ├── authorization/
│   ├── business-logic/
│   ├── critical/
│   ├── high/
│   ├── medium/
│   ├── low/
│   └── misconfiguration/
│
├── terminal/
│   ├── __init__.py
│   ├── cli.py
│   └── dashboard.py
│
├── config/
├── tests/
├── tools/
│
├── main.py
├── requirements.txt
├── requirements-lock.txt
├── .gitignore
└── README.md
```

### Important components

### `engine/scanner.py`

This is the primary scanner implementation.

It is responsible for:

* Loading templates.
* Preparing template execution.
* Rendering request values.
* Executing HTTP requests.
* Processing responses.
* Applying detection conditions.
* Collecting evidence.
* Producing scan results.
* Tracking request and template execution information.

The scanner currently loads the repository's valid YAML templates recursively from the template directory.

### `core/database.py`

This is the persistence layer.

VulnForge uses SQLite rather than storing scan results only in terminal output or log files.

The database contains information about:

* Scans
* Findings
* Finding severity
* Evidence
* Confirmation state
* Exploitation state
* Confidence
* Scan timestamps
* Request counts
* Template counts
* Scan duration
* Scan status

### `terminal/cli.py`

The CLI provides the primary command-line interface for starting scans and interacting with stored results.

### `terminal/dashboard.py`

The dashboard provides a visual representation of the information already stored by VulnForge.

This is important architecturally:

```text
Scanner
   │
   ▼
SQLite
   │
   ▼
Dashboard
```

The dashboard does not need to invent scan results.

It reads the persisted scan and finding data and presents it in a more useful form.

### `core/report.py`

Provides report-generation and analysis functionality based on collected scan information.

### `engine/recon/`

Contains the project's reconnaissance-related components.

The current module is separated into:

```text
crawler.py
parser.py
models.py
scope.py
```

This keeps reconnaissance-related functionality separate from the core template execution engine.

---

# 6. Database Design

SQLite is a central part of the project.

The database file is local:

```text
vulnforge.db
```

It is intentionally excluded from Git because scan results are generated data and may contain target-specific information.

The current database contains three primary tables:

```text
scans
findings
fingerprints
```

The relationship between the important tables is:

```text
                 ┌─────────────────┐
                 │      scans      │
                 ├─────────────────┤
                 │ scan_id         │
                 │ target          │
                 │ timestamp       │
                 │ status          │
                 │ findings_count  │
                 │ templates_loaded│
                 │ requests_sent   │
                 │ scan_duration   │
                 └────────┬────────┘
                          │
                     scan_id
                          │
                          ▼
                 ┌─────────────────┐
                 │    findings     │
                 ├─────────────────┤
                 │ id              │
                 │ scan_id         │
                 │ template_id     │
                 │ name            │
                 │ severity        │
                 │ evidence        │
                 │ confirmed       │
                 │ confidence      │
                 │ remediation     │
                 │ endpoint        │
                 │ method          │
                 └─────────────────┘
```

This allows multiple scans to be retained while keeping their findings associated with the correct scan.

For example:

```text
Scan A
 ├── Finding 1
 ├── Finding 2
 └── Finding 3

Scan B
 ├── Finding 1
 └── Finding 2
```

The database therefore becomes the persistent source of truth for the dashboard and reporting components.

---

# 7. Scan Lifecycle

A typical VulnForge scan follows this sequence.

## Step 1 — Target

The user supplies an authorized target:

```bash
python main.py -u https://example.com
```

## Step 2 — Scanner initialization

The scanner initializes the target, configuration, request handling, and scan state.

## Step 3 — Template loading

The scanner recursively searches the configured template directory.

YAML files are loaded only when they satisfy the expected template structure.

For example:

```text
templates/
├── authorization/
├── critical/
├── high/
├── medium/
└── low/
```

Templates inside disabled or excluded directories are not loaded as active templates.

## Step 4 — Template execution

Each valid template is executed against the target according to its request definition.

## Step 5 — HTTP response processing

The scanner receives the response and makes it available to the template matching and extraction logic.

## Step 6 — Matching

Matchers determine whether the response satisfies the conditions defined by the template.

Examples include:

* HTTP status
* Response body words
* Regular expressions
* Other template-defined conditions

## Step 7 — Extraction

When required, values can be extracted from responses and reused later.

Conceptually:

```text
Request 1
   │
   ▼
Response
   │
   ▼
Extract value
   │
   ▼
Template context
   │
   ▼
Request 2
```

This allows multi-step security checks rather than restricting every template to a single request.

## Step 8 — Finding creation

When a template produces a detection result, VulnForge creates a finding containing information such as:

* Template ID
* Finding name
* Severity
* Evidence
* Endpoint
* HTTP method
* Response information
* Confidence
* Confirmation state
* Remediation information

## Step 9 — Persistence

The scan and its findings are written to SQLite.

The scan record stores aggregate information such as:

```text
scan_id
target
timestamp
status
findings_count
templates_loaded
requests_sent
errors_count
scan_duration
confirmed_count
```

## Step 10 — Dashboard / Reporting

The stored results can then be viewed through the dashboard or processed for reporting.

---

# 8. Understanding Findings

A critical distinction in VulnForge is the difference between a **template match** and a **confirmed vulnerability**.

A scanner can observe behavior that appears suspicious without having enough evidence to establish a vulnerability conclusively.

Therefore:

```text
Template Match
      │
      ▼
Potential Finding
      │
      ▼
Evidence / Verification
      │
      ▼
Confirmed Finding
```

The number displayed as total findings represents findings produced by the scan according to the scanner's detection and correlation logic.

It should not automatically be interpreted as the number of independently verified security vulnerabilities.

This distinction is important when using the framework for real security testing.

---

# 9. Template System

Templates are stored under:

```text
templates/
```

They are grouped by vulnerability category and severity.

The current repository contains templates covering areas including:

### Authorization

* BOLA
* IDOR
* UUID-based authorization checks
* Function-level authorization

### Injection

* SQL injection
* Blind SQL injection
* NoSQL injection
* Command injection
* SSTI

### API Security

* BOLA
* Mass assignment
* Authorization-related API checks

### Cross-Site Scripting

* Reflected XSS
* Stored XSS

### Authentication and Configuration

* CSRF
* JWT configuration
* OAuth configuration
* CORS

### Server-Side Issues

* SSRF
* Path traversal

### Exposure / Misconfiguration

* Environment-file exposure
* Git exposure
* Server information disclosure
* Security-header checks
* Public exposure checks

### Other Checks

* GraphQL introspection
* Open redirect
* File-upload checks
* Business-logic checks

The exact template count is not treated as a permanent project specification because templates can be added or removed.

At the current project state, the scanner successfully loaded:

```text
45 templates
```

with:

```text
45 valid
0 disabled loaded
```

The scanner output should be considered authoritative when the repository changes.

---

# 10. Example Template

A simplified VulnForge template follows this general structure:

```yaml
id: example-check
name: Example Security Check
severity: medium

impact: |
  Describes the potential security impact.

requests:
  - method: GET
    path:
      - "/example"

    matchers:
      - type: status
        status:
          - 200

      - type: word
        part: body
        words:
          - "example"
```

The exact fields available to a template depend on the template runtime implemented by VulnForge.

---

# 11. Template Loading

Templates are loaded recursively.

For example:

```text
templates/
├── authorization/
│   ├── bola-graphql.yaml
│   ├── bola-numeric.yaml
│   └── function-level-auth.yaml
│
├── critical/
│   ├── injection/
│   └── server-side/
│
├── high/
├── medium/
└── low/
```

This means new templates can be organized into subdirectories without changing the scanner's template discovery code.

A template must contain the required structure before it is accepted by the loader.

This validation prevents malformed YAML files from becoming active scan templates.

---

# 12. Reconnaissance Components

VulnForge also contains a reconnaissance module:

```text
engine/recon/
├── crawler.py
├── parser.py
├── models.py
└── scope.py
```

The purpose of this module is to separate target discovery and parsing concerns from vulnerability-template execution.

The separation is intentional:

```text
Reconnaissance
      │
      ▼
Target / Endpoint Information
      │
      ▼
Security Testing
      │
      ▼
Findings
```

This provides a foundation for expanding VulnForge beyond isolated template requests.

---

# 13. Dashboard

The dashboard is intended to make persisted scan information easier to analyze.

Instead of reading a large terminal output such as:

```text
scan → request → response → finding
```

the dashboard organizes the stored information into a visual interface.

The dashboard can present information such as:

* Total scans
* Findings
* Severity distribution
* Confirmed findings
* Scan history
* Target information
* Scan duration
* Templates loaded
* Requests sent
* Individual finding details
* Evidence and remediation information

The important design relationship is:

```text
                    ┌─────────────┐
                    │   Scanner   │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   SQLite    │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       ┌─────────────┐           ┌─────────────┐
       │  Dashboard  │           │   Reports   │
       └─────────────┘           └─────────────┘
```

This allows the same scan data to be consumed by different interfaces.

---

# 14. Installation

## Requirements

Recommended environment:

* Python 3.10+
* Git
* pip
* Linux, macOS, or Windows
* Network access when testing remote authorized targets

For security research, Linux is the preferred development environment.

---

## Clone the repository

```bash
git clone https://github.com/nisanbudhathoki21/VulnForge.git
cd VulnForge
```

## Create a virtual environment

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

## Install dependencies

```bash
pip install -r requirements.txt
```

If using the locked dependency file:

```bash
pip install -r requirements-lock.txt
```

---

# 15. Verify the Installation

Check the command-line interface:

```bash
python main.py --help
```

Verify that the scanner can be imported:

```bash
python - <<'PY'
from engine.scanner import Scanner

scanner = Scanner("https://example.com")
templates = scanner.load_templates()

print("Templates loaded:", len(templates))
PY
```

The number printed depends on the templates currently present in the repository.

---

# 16. Running a Scan

For an authorized target:

```bash
python main.py -u https://example.com
```

The scanner will:

```text
Initialize
   ↓
Load templates
   ↓
Execute requests
   ↓
Process responses
   ↓
Match detection rules
   ↓
Create findings
   ↓
Store scan in SQLite
```

For local testing:

```bash
python main.py -u http://127.0.0.1:5001
```

Local deliberately vulnerable applications are recommended while developing and debugging new templates.

---

# 17. Viewing Scan History

Scan information is stored in:

```text
vulnforge.db
```

The database is local and intentionally ignored by Git.

You can inspect the database directly with SQLite:

```bash
sqlite3 vulnforge.db
```

Then:

```sql
.tables
```

The primary tables include:

```text
findings
fingerprints
scans
```

Inspect the scan schema:

```bash
sqlite3 vulnforge.db ".schema scans"
```

Inspect findings:

```bash
sqlite3 vulnforge.db ".schema findings"
```

Example query:

```sql
SELECT
    scan_id,
    target,
    findings_count,
    templates_loaded,
    requests_sent,
    status
FROM scans;
```

---

# 18. Working With the Database

A typical stored scan contains information similar to:

```text
scan_id
target
timestamp
start_time
end_time
fingerprint
findings_count
scan_duration
status
scan_depth
templates_loaded
requests_sent
errors_count
confirmed_count
```

A finding contains information such as:

```text
id
scan_id
template_id
name
severity
impact
evidence
extracted
confirmed
exploit_attempted
exploit_success
confidence
cwe
owasp
remediation
endpoint
method
http_status
details
```

This structure allows the project to retain more than a simple vulnerability count.

---

# 19. Reporting

The reporting layer consumes stored scan information rather than requiring the scanner to regenerate the scan.

This separation allows:

```text
One scan
   │
   ├── Dashboard
   ├── CLI output
   └── Report
```

The exact reporting commands should be checked with:

```bash
python main.py --help
```

because reporting options may evolve as the project develops.

---

# 20. Optional Local AI Analysis

VulnForge can integrate with local AI tooling where the corresponding reporting functionality is enabled.

One possible local setup uses Ollama.

After installing Ollama, verify available models:

```bash
ollama list
```

A configured model can then be used by the project's AI reporting functionality.

AI output should not be treated as proof of a vulnerability.

The correct workflow remains:

```text
Scanner detection
       ↓
Collected evidence
       ↓
Manual verification
       ↓
Security conclusion
```

AI can assist with interpretation and report writing, but it should not replace technical verification.

---

# 21. Testing the Project

Before modifying the scanner, it is useful to verify the basic runtime.

### Template loading

```bash
python - <<'PY'
from engine.scanner import Scanner

scanner = Scanner("https://example.com")
templates = scanner.load_templates()

print("Templates loaded:", len(templates))

for template in templates:
    print(template.get("id"))
PY
```

### Python compilation

```bash
python -m py_compile engine/scanner.py
python -m py_compile core/database.py
python -m py_compile core/report.py
python -m py_compile terminal/cli.py
python -m py_compile terminal/dashboard.py
```

### Template validation

If the repository contains the validation utility:

```bash
python tools/validate_templates.py
```

The expected template count should be taken from the actual repository state rather than hard-coded into the documentation.

---

# 22. Safe Development Environment

New templates should first be tested against intentionally vulnerable applications.

Suitable environments include:

* OWASP Juice Shop
* DVWA
* OWASP WebGoat
* Locally developed vulnerable applications

For example:

```bash
python main.py -u http://127.0.0.1:3000
```

when the test application is running locally.

This makes template development reproducible and avoids accidentally testing systems outside the researcher's authorization.

---

# 23. Developing a New Template

The recommended development process is:

```text
Identify vulnerability
        ↓
Study expected behavior
        ↓
Create YAML template
        ↓
Validate template
        ↓
Run against controlled target
        ↓
Inspect HTTP evidence
        ↓
Verify detection
        ↓
Store / review finding
        ↓
Document the template
```

A new template should have a clear relationship between:

```text
Request
   ↓
Expected behavior
   ↓
Matcher
   ↓
Evidence
   ↓
Security interpretation
```

A matcher should not be chosen merely because a response contains an interesting string.

The response should provide evidence relevant to the vulnerability being tested.

---

# 24. False Positives and Verification

Automated security testing always involves a trade-off between coverage and confidence.

A response matching a detection rule does not necessarily mean that the underlying vulnerability exists.

For example:

```text
HTTP 200
+
interesting response text
=
detection signal
```

does not automatically equal:

```text
confirmed vulnerability
```

VulnForge therefore records information that can be used during manual verification.

For research and bug-bounty work, the final conclusion should be based on reproducible evidence rather than the scanner's label alone.

---

# 25. Performance and Request Control

Security scanners can generate significant HTTP traffic.

VulnForge therefore includes request-control mechanisms where supported by the current implementation, including configuration related to:

* Request timeout
* Delay
* Rate limiting
* Jitter
* Worker concurrency
* Proxy configuration

These controls should be configured according to the authorization and rate limits of the target.

For bug-bounty programs, the program's published scope and testing policy always take precedence over scanner configuration.

---

# 26. Security and Privacy

The SQLite database can contain target information and security evidence.

For that reason:

```text
vulnforge.db
```

and generated local scan artifacts should not be committed to the public repository.

The repository `.gitignore` excludes local database and generated dashboard/report artifacts.

This keeps:

```text
Source Code
Templates
Documentation
```

separate from:

```text
Target Data
Scan History
Evidence
Generated Reports
```

---

# 27. Limitations

VulnForge is a research-oriented, template-driven security testing framework.

It does not guarantee complete vulnerability discovery.

Detection depends on:

* Target architecture
* Available endpoints
* Authentication state
* Application behavior
* Template quality
* Response behavior
* Scope of the scan
* Detection logic
* Manual verification

In particular, a template-based scanner cannot understand every application's business logic automatically.

Complex vulnerabilities often require application-specific knowledge and manual testing.

Therefore:

> **No findings does not mean the application is secure.**

Likewise:

> **A finding does not automatically mean a vulnerability has been confirmed.**

---

# 28. Responsible Use

VulnForge is intended for:

* Academic security research
* Authorized penetration testing
* Bug-bounty testing within program scope
* Security testing of applications owned by the operator
* Deliberately vulnerable laboratory environments

Do not scan systems without permission.

The operator is responsible for complying with:

* Applicable laws
* Bug-bounty program rules
* Target scope
* Rate limits
* Authentication requirements
* Responsible disclosure requirements

---

# 29. Project Status

VulnForge is an actively developed security research project.

The current implementation includes:

```text
YAML template engine       Implemented
Recursive template loading Implemented
HTTP security testing      Implemented
Matchers                   Implemented
Extraction support         Implemented
Finding generation        Implemented
SQLite persistence         Implemented
Scan history               Implemented
Recon module               Implemented
CLI                        Implemented
Dashboard                  Implemented
Reporting                  Implemented
Optional AI analysis      Supported where configured
```

The repository currently contains a template collection spanning authorization, injection, API security, XSS, authentication, server-side issues, exposure, configuration, and business-logic testing.

The project is still evolving, so implementation details and template coverage may change.

---

# 30. Research Direction

The long-term direction of VulnForge is to develop the project from a simple template executor into a more complete security testing framework.

Areas of continued development include:

```text
Reconnaissance
      ↓
Endpoint discovery
      ↓
Template selection
      ↓
Context-aware testing
      ↓
Detection
      ↓
Verification
      ↓
Correlation
      ↓
Evidence
      ↓
Persistent findings
      ↓
Reporting / Dashboard
```

The goal is not simply to increase the number of templates.

A useful security testing framework should improve the relationship between:

**target discovery → testing → evidence → verification → analysis.**

---

# 31. Contributing

Contributions are welcome.

Useful areas include:

* Vulnerability templates
* Template validation
* Matchers
* Extractors
* Scanner reliability
* Reconnaissance
* Database improvements
* Finding correlation
* Dashboard improvements
* Report generation
* Test coverage
* Documentation

When adding a template, it should be tested against an authorized or intentionally vulnerable environment before being considered reliable.

---

# 32. License

See the repository's `LICENSE` file for the applicable license.

---

# 33. Project Repository

**VulnForge**

[GitHub Repository](https://github.com/nisanbudhathoki21/VulnForge?utm_source=chatgpt.com)

VulnForge is developed as a security research and academic project focused on understanding and implementing the architecture of automated web application security testing.

---

## Summary

VulnForge combines:

```text
YAML Templates
      +
HTTP Testing
      +
Matchers / Extractors
      +
Finding Generation
      +
SQLite Persistence
      +
Reconnaissance
      +
CLI
      +
Dashboard
      +
Reporting
```

into one local security-testing workflow.

The central idea is straightforward:

> **Define security checks as reusable templates, execute them through a common scanner engine, preserve the resulting evidence in a database, and make the results available for analysis through the CLI, dashboard, and reporting components.**
