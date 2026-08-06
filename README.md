## Screenshot

![VulnForge scan output](docs/screenshots/scan-output.png)

# VulnForge

VulnForge is a lightweight, template-driven security research CLI for safe, non-destructive vulnerability discovery, correlation, and reporting.

It is **not** a mass scanner. It focuses on producing a small number of well-evidenced findings, distinguishing clearly between what was directly verified and what merely warrants manual investigation.

## Status

Early-stage / actively developed. Core pipeline (recon → detection → correlation → persistence → reporting) is functional. Detection template library is intentionally small right now — see [Roadmap](#roadmap).

## Features

- **YAML-based detection templates** — each template defines one or more HTTP requests and matcher rules (header presence/absence, status code, regex, response timing).
- **Finding classification** — every finding is labeled `Verified`, `Possible`, `Related`, or `Investigation`. Nothing is presented as confirmed unless it was directly observed.
- **Correlation engine** — links related findings (same endpoint, foundational weaknesses amplifying higher-severity issues, auth-adjacent API findings) into investigation paths with reasoning and estimated time.
- **Local persistence** — findings and investigation paths are saved to a local SQLite database (`vulnforge.db`), linked by scan ID, so results aren't lost between runs.
- **Scan history** — query past findings via `--history`.
- **Markdown report generation** — generate a per-finding, disclosure-style Markdown report from any past scan via `--report`.
- **Rich terminal output** — phase-based scan log with color-coded severity tags and a summary bar (requests, errors, findings, elapsed time).

## Installation

```bash
git clone https://github.com/nisanbudhathoki21/VulnForge.git
cd VulnForge
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

> **Note:** Verify the `VulnForge` command resolves correctly after install with `which VulnForge`. If it's not found, run the CLI directly instead: `python main.py -u https://target.example`.

## Usage

Run a scan:
```bash
VulnForge -u https://target.example
```

Run a scan with JSON output (for scripting/piping):
```bash
VulnForge -u https://target.example --json
```

View past scan findings:
```bash
VulnForge --history
VulnForge --history --scan-id <scan_id> --json
```

Generate a Markdown report from a past scan:
```bash
VulnForge --report <scan_id>
```
Reports are written to `output/`.

## Architecture

correlation/ Correlation engine — links findings into investigation paths
database/ SQLAlchemy models + repository for scan persistence
httpclient/ Async HTTP client (httpx-based)
matcher/ Matcher engine — evaluates template rules against responses
report/ Markdown report generation
scanner/ Template execution engine
templates/ YAML detection template loader + schema
templates/*/ The actual detection templates, organized by severity/category
terminal/ CLI entrypoint + Rich-based terminal UI
workspace/ Core data models (Finding, Evidence)
