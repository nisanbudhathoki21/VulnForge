# 🛡️ VulnForge

**YAML-driven web application vulnerability scanner and security testing framework.**

VulnForge is a Python-based security testing framework designed to automate repeatable web application vulnerability checks using YAML templates.

It combines a template execution engine, HTTP request handling, response matching, extraction, contextual variable rendering, evidence collection, scan persistence, and reporting into a single workflow.

> **For authorized security testing only.**
>
> Only scan applications, APIs, and infrastructure that you own or have explicit permission to test.

---

## ✨ Features

| Feature                        | Description                                                                   |
| ------------------------------ | ----------------------------------------------------------------------------- |
| 🔍 **Template-Based Scanning** | Execute reusable YAML security-testing templates against a target.            |
| 🧩 **Template Runtime**        | Supports variables, filters, arithmetic expressions, and recursive rendering. |
| 🔐 **Authorization Testing**   | Templates for BOLA/IDOR and function-level authorization testing.             |
| 💉 **Injection Testing**       | SQL injection, NoSQL injection, command injection, SSTI, and related checks.  |
| 🌐 **API Security Testing**    | API-focused checks including BOLA and mass-assignment patterns.               |
| 🕸️ **XSS Testing**            | Reflected, stored, and DOM-oriented XSS templates.                            |
| 🔄 **Multi-Stage Templates**   | Extract values from one response and reuse them in subsequent requests.       |
| 🎯 **Matchers**                | Match HTTP status codes, response words, and regular expressions.             |
| 📤 **Extractors**              | Extract JSON, regular-expression, and raw values into template context.       |
| 🧾 **Evidence Collection**     | Stores request and response information associated with findings.             |
| 🗄️ **SQLite Persistence**     | Maintains scan and finding information locally.                               |
| ⚡ **Concurrent Execution**     | Executes templates using a configurable worker pool.                          |
| ⏱️ **Rate Limiting**           | Supports request rate limits, delays, and jitter.                             |
| 🌍 **Proxy Support**           | Supports proxy configuration and optional country-based proxy selection.      |
| 🔬 **Optional Exploitation**   | Templates can define optional proof-of-concept exploitation steps.            |
| 🤖 **Optional AI Reporting**   | Supports local AI-assisted reporting where configured.                        |
| 🧪 **Template Validation**     | Validates template structure before scanning.                                 |

---

# 🏗️ Architecture

VulnForge follows a modular scanning architecture:

```text
                    ┌─────────────────────┐
                    │     CLI Interface   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Scanner Engine    │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
      ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
      │ Template     │ │ HTTP Client  │ │ Auth Manager │
      │ Runtime      │ │ / Sessions   │ │              │
      └──────┬───────┘ └──────┬───────┘ └──────────────┘
             │                │
             ▼                ▼
      ┌──────────────┐ ┌──────────────┐
      │ YAML         │ │ Requests /   │
      │ Templates    │ │ Responses    │
      └──────┬───────┘ └──────┬───────┘
             │                │
             └────────┬───────┘
                      ▼
               ┌──────────────┐
               │   Matchers   │
               │  Extractors  │
               └──────┬───────┘
                      │
                      ▼
               ┌──────────────┐
               │   Findings   │
               │   Evidence   │
               └──────┬───────┘
                      │
             ┌────────┴────────┐
             ▼                 ▼
      ┌──────────────┐  ┌──────────────┐
      │ SQLite       │  │ Reporting    │
      │ Persistence  │  │ / Analysis   │
      └──────────────┘  └──────────────┘
```

---

# 📁 Project Structure

```text
VulnForge/
├── ai/                     # Optional AI analysis
├── config/                 # Configuration
├── core/                   # Core helpers and verification logic
├── correlation/            # Finding correlation
├── database/               # SQLite persistence
├── engine/
│   ├── scanner.py          # Main scanner engine
│   ├── template_runtime.py # Template expression/rendering engine
│   └── template_validator.py
├── extractor/              # Extraction components
├── httpclient/             # HTTP functionality
├── matcher/                # Response matching
├── risk/                   # Risk/severity processing
├── scanner/                # Supporting scanner components
├── templates/              # YAML vulnerability templates
├── terminal/               # CLI interface
├── tests/                  # Runtime and integration tests
├── tools/                  # Developer utilities
├── reports/                # Report generation
├── workspace/              # Scan workspace functionality
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
└── README.md
```

---

# 📦 Installation

## Requirements

* Python **3.10+**
* Git
* pip
* Internet access for remote targets
* Linux/macOS/Windows with Python support

Optional:

* Ollama for local AI-assisted analysis
* WeasyPrint if PDF reporting is enabled by the installed report stack

---

## 1. Clone the Repository

```bash
git clone https://github.com/nisanbudhathoki21/VulnForge.git
cd VulnForge
```

## 2. Create a Virtual Environment

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

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

If the project is configured as an installable Python package:

```bash
pip install -e .
```

## 4. Verify the Installation

First check the CLI:

```bash
python main.py --help
```

If the package installs a `VulnForge` command, you can alternatively use:

```bash
VulnForge --help
```

Use whichever entry point is provided by the current installation.

---

# 🚀 Quick Start

## Scan a Target

```bash
python main.py -u https://example.com
```

Or, if the installed CLI command is available:

```bash
VulnForge -u https://example.com
```

Only use targets for which you have authorization.

---

## Scan Multiple Targets

Create a file:

```text
targets.txt
```

Example:

```text
https://example.com
https://example.org
https://test.example.net
```

Then:

```bash
python main.py -l targets.txt
```

---

# 🧩 YAML Templates

VulnForge uses YAML templates to define security checks.

Templates are organized by vulnerability category:

```text
templates/
├── authorization/
├── business-logic/
├── critical/
├── high/
├── medium/
├── low/
└── starbucks-jp/
```

The current repository contains **45 validated templates**.

Validate them with:

```bash
python tools/validate_templates.py
```

Expected result:

```text
Valid templates   : 45
Invalid templates : 0
```

The exact number may change as templates are added or removed.

---

# 🧠 Template Runtime

The template runtime supports contextual variables and filters.

For example:

```text
{{own_id}}
```

can resolve to:

```text
100
```

Filters can transform values:

```text
{{own_id|int}}
{{own_id|str}}
{{own_id|hex}}
{{own_id|base64}}
```

Arithmetic expressions can also be used:

```text
{{own_id|int+1}}
{{own_id|int-1}}
```

For example:

```text
/api/users/{{own_id|int+1}}
```

can render as:

```text
/api/users/101
```

The runtime also recursively renders nested lists and dictionaries.

---

# 📝 Example Template

A simplified template looks like:

```yaml
id: example-01
name: Example Security Check
severity: medium

impact: |
  Example security impact.

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

Place valid YAML templates anywhere under the configured template directory.

---

# 🔄 Multi-Stage Testing

Templates can extract information from responses and reuse it later.

Conceptually:

```text
Request 1
   │
   ▼
Response
   │
   ├── Extract user_id
   │
   ▼
Request 2
   │
   └── Use {{user_id}}
```

Supported extraction mechanisms include:

* JSON extraction
* Regular-expression extraction
* Raw/context values

This allows templates to model workflows rather than only isolated HTTP requests.

---

# 🔍 Matchers

Matchers determine whether a response satisfies the conditions defined by a template.

Supported matcher types include:

### Status

```yaml
matchers:
  - type: status
    status:
      - 200
```

### Word

```yaml
matchers:
  - type: word
    part: body
    words:
      - "administrator"
```

### Regular Expression

```yaml
matchers:
  - type: regex
    part: body
    regex:
      - "user_[0-9]+"
```

Templates can combine multiple matchers using matcher conditions.

---

# 📊 Findings and Evidence

When a template matches, VulnForge can record evidence including:

* HTTP method
* Request URL
* Request headers
* Request body
* Response status
* Response headers
* Response body
* Response length
* Extracted template variables
* Template identifier
* Severity
* Impact information
* Optional exploitation result

This provides reproducible evidence for security testing and later reporting.

---

# 🗄️ Scan Persistence

VulnForge uses SQLite for local scan persistence.

The database allows scan information and findings to be retained between executions.

Example:

```bash
python main.py --history
```

To inspect a specific scan:

```bash
python main.py --scan-id <SCAN_ID>
```

---

# 📄 Reporting

Depending on the configured reporting components, VulnForge can generate structured reports from saved scan results.

Example:

```bash
python main.py --report <SCAN_ID> --format html
```

Markdown:

```bash
python main.py --report <SCAN_ID> --format md
```

PDF support depends on the project's installed reporting dependencies:

```bash
python main.py --report <SCAN_ID> --format pdf
```

Before relying on a particular format, verify that the corresponding reporting dependency is installed.

---

# 🤖 Optional AI Analysis

VulnForge can optionally integrate with local AI tooling for analysis and report assistance.

One supported approach is **Ollama**.

Install Ollama from its official website and then pull a model:

```bash
ollama pull llama3.2
```

Verify:

```bash
ollama list
```

If your installed VulnForge CLI exposes the AI reporting options, use:

```bash
python main.py --report <SCAN_ID> \
  --ai \
  --ai-provider ollama \
  --ai-model llama3.2 \
  --format html
```

AI-generated text should be treated as assistance rather than authoritative security evidence. Findings should be manually verified before being reported.

---

# 🧪 Testing

VulnForge includes tests for the template runtime and scanner execution.

Run the runtime test from the repository root:

```bash
PYTHONPATH=. python tests/test_template_runtime.py
```

Run template execution testing:

```bash
PYTHONPATH=. python tests/test_template_execution.py
```

Run scanner runtime testing:

```bash
PYTHONPATH=. python tests/test_scanner_runtime.py
```

Validate all templates:

```bash
python tools/validate_templates.py
```

Compile the main runtime components:

```bash
python -m py_compile \
  engine/scanner.py \
  engine/template_runtime.py \
  engine/template_validator.py
```

Current validation status:

```text
Template runtime       PASS
Template execution     PASS
Scanner runtime        PASS
Template validation    45 valid / 0 invalid
Python compilation     PASS
```

---

# 🎯 Vulnerability Coverage

The current template collection includes checks covering areas such as:

### Authorization

* BOLA
* IDOR
* UUID-based object authorization
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
* API authorization issues

### Cross-Site Scripting

* Reflected XSS
* Stored XSS
* DOM-oriented XSS

### Authentication / Configuration

* CSRF
* JWT configuration issues
* OAuth configuration issues
* CORS

### Server-Side Issues

* SSRF
* Path traversal

### Information Exposure

* Environment file exposure
* Git exposure
* Server information disclosure
* Security-header checks

### Other

* GraphQL introspection
* Open redirect
* File upload checks
* Business-logic testing

Coverage is template-driven and therefore depends on the quality of the template, target behavior, and available application context. A template match is **not automatically proof of a confirmed vulnerability**.

---

# ⚙️ Proxy and Request Controls

VulnForge supports configurable request behavior.

Example proxy file:

```text
http://127.0.0.1:8080
```

Use:

```bash
python main.py -u https://example.com \
  --proxy-file proxies.txt
```

Country-based proxy selection can be configured when the proxy file contains country metadata supported by the scanner.

Request pacing can be controlled using:

```bash
--rate-limit
--delay
--jitter
--timeout
```

These controls should be used to prevent unnecessary load on authorized targets.

---

# 🔐 Authentication

VulnForge can operate with authentication information supplied through the CLI where supported by the current implementation.

It also contains authentication helpers for supported registration/login workflows.

Authentication behavior is application-dependent. VulnForge cannot automatically understand every application's custom authentication architecture.

For applications requiring complex authentication flows, manually obtained credentials/session information may be necessary.

---

# 🧪 Recommended Test Environments

For safe development and testing, use deliberately vulnerable applications such as:

* OWASP Juice Shop
* OWASP WebGoat
* DVWA

For example:

```bash
python main.py -u http://127.0.0.1:3000
```

when Juice Shop is running locally.

Local vulnerable applications are preferable when developing new templates because they avoid accidentally testing unauthorized production systems.

---

# 🛠️ Development Workflow

A typical workflow for adding a new vulnerability template is:

```text
1. Create YAML template
        ↓
2. Validate YAML structure
        ↓
3. Run template runtime tests
        ↓
4. Test against an authorized vulnerable target
        ↓
5. Review evidence
        ↓
6. Add/update documentation
        ↓
7. Commit changes
```

Validate templates with:

```bash
python tools/validate_templates.py
```

---

# ⚠️ Limitations

VulnForge is a template-driven security testing framework. It does **not** guarantee detection of every vulnerability.

Detection quality depends on:

* Template quality
* Application architecture
* Authentication state
* Endpoint discovery
* Response behavior
* Request context
* Server-side protections
* Application-specific business logic

A scanner finding should be manually reviewed before being treated as a confirmed security vulnerability.

Similarly, the absence of a finding does not prove that a target is secure.

---

# 🛡️ Responsible Use

VulnForge is intended for:

* Authorized penetration testing
* Bug bounty programs within their published scope
* Security research on systems you own
* Local vulnerable applications
* Academic and educational security testing

Do not use VulnForge against systems without authorization.

The operator is responsible for complying with applicable laws, program rules, rate limits, and scope restrictions.

---

# 🤝 Contributing

Contributions are welcome.

Useful contributions include:

* New vulnerability templates
* Improved matchers
* Better extractors
* Runtime improvements
* Test coverage
* Documentation improvements
* Bug fixes

When submitting a new template, include:

* Unique template ID
* Vulnerability name
* Severity
* Request definition
* Matchers
* Extractors where required
* Reproducible testing evidence

---

# 📜 License

This project is licensed under the MIT License.

See:

```text
LICENSE
```

for the complete license text.

---

# 👤 Project

**VulnForge**

GitHub:

https://github.com/nisanbudhathoki21/VulnForge

Developed as a security research and academic project.

---

## ⭐ Project Status

Current repository validation:

```text
Scanner compilation       PASS
Template runtime          PASS
Template execution        PASS
Scanner runtime           PASS
Templates validated       45
Invalid templates         0
```

VulnForge is actively being developed. Features and template coverage may change between releases.

---

**VulnForge — YAML-driven security testing, built for repeatable web application analysis.**
