🛡️ VulnForge Ultimate v1

Template-Driven Web Application Security Testing Framework

VulnForge Ultimate v1 is a Python-based security research and web application assessment framework built around reusable YAML detection templates, HTTP request execution, response matching, evidence collection, SQLite persistence, scan analysis, reporting, and a local dashboard.

Authorized testing only. Use VulnForge Ultimate only against systems you own, intentionally vulnerable labs/CTFs, or targets for which you have explicit permission to test.

Table of Contents

Overview

Core Workflow

Features

Requirements

Installation

CLI Usage

Live Dashboard

SQLite Database

Scan and Dashboard Workflow

Reports

Project Structure

Troubleshooting

Responsible Use

License

Overview

VulnForge Ultimate v1 separates the scanner engine from individual detection definitions.

Instead of hard-coding every security check into Python, detection logic can be represented by YAML templates. The scanner loads those templates, renders requests, sends them to an authorized target, evaluates responses, extracts evidence, and creates findings.

Authorized Target
       │
       ▼
Scanner / CLI
       │
       ▼
YAML Templates
       │
       ▼
HTTP Request
       │
       ▼
HTTP Response
       │
       ├───────────────┐
       ▼               ▼
   Matchers       Extractors
       │               │
       └───────┬───────┘
               ▼
            Finding
               │
       ┌───────┴────────┐
       ▼                ▼
 SQLite Database     Reports
       │
       ▼
 Local Dashboard

Core Workflow

Load the configured detection templates.

Discover or receive the target endpoint.

Render the template request.

Send the request using the HTTP layer.

Evaluate the response with matchers.

Extract useful evidence where configured.

Create a finding.

Persist scan/finding information to SQLite.

Review results through the CLI or dashboard.

Generate reports when required.

Features

YAML-driven vulnerability templates

HTTP/HTTP2 support

Response matchers

Data extraction

Evidence collection

SQLite scan persistence

CLI scanning

Local dashboard

Reporting support

Correlation and analysis components

Optional AI-assisted analysis

Extensible project structure

Repeatable security-testing workflow

Requirements

Recommended environment:

Linux

Python 3.10+

python3-venv

Git

SQLite 3

Kali Linux, Debian, and Ubuntu are suitable environments.

Installation

1. Clone the Repository

git clone https://github.com/nisanbudhathoki21/VulnForge.git
cd VulnForge

If the repository contains VulnForge Ultimate as a subdirectory, enter the Ultimate directory before installing it.

For the repository layout where Ultimate is located under VulnForge_Ultimate/:

cd VulnForge_Ultimate

Verify:

pwd
ls -la

You should see files such as:

core/
engine/
templates/
terminal/
requirements.txt
setup.py
README.md

If your local Ultimate release also contains run.sh, you should see that file as well.

2. Install Python Virtual Environment Support

On Kali/Debian:

sudo apt update
sudo apt install -y python3-venv python3-pip git sqlite3

3. Create the Virtual Environment

From the VulnForge Ultimate project directory:

python3 -m venv .venv

Activate it:

source .venv/bin/activate

Verify:

which python
python --version

4. Upgrade pip

python -m pip install --upgrade pip

5. Install Dependencies

pip install -r requirements.txt

6. Install VulnForge Ultimate

Install the package in editable mode:

pip install -e .

Verify:

which VulnForge
VulnForge --help

The editable installation is useful for development because source changes are immediately reflected in the installed package.

CLI Usage

Basic scan:

VulnForge -u https://authorized-target.example

Local development target:

VulnForge -u http://127.0.0.1:3000

Specify workers/threads when supported by the installed release:

VulnForge -u http://127.0.0.1:3000 -t 10

Use only authorized targets.

Live Dashboard

Some VulnForge Ultimate releases include a run.sh launcher for the interactive dashboard.

From the directory containing run.sh:

cd ~/VulnForge_Ultimate
source .venv/bin/activate
chmod +x run.sh
./run.sh

A successful startup looks similar to:

[+] Starting Interactive Dashboard on http://0.0.0.0:8000
[*] Starting VulnForge Ultimate Live Dashboard on http://0.0.0.0:8000
INFO:     Uvicorn running on http://0.0.0.0:8000

Open the dashboard in your browser:

http://127.0.0.1:8000

or:

http://localhost:8000

Why 0.0.0.0?

0.0.0.0 is the server bind address. For a local browser, use 127.0.0.1 or localhost.

Important

Run:

./run.sh

not:

run.sh

The ./ tells the shell to execute the script from the current directory.

If your particular release does not contain run.sh, do not create one blindly. Check the repository's available launcher/server files first.

Two-Terminal Workflow

Terminal 1 — Dashboard

cd ~/VulnForge_Ultimate
source .venv/bin/activate
./run.sh

Keep it running.

Terminal 2 — Scanner

cd ~/VulnForge_Ultimate
source .venv/bin/activate
VulnForge -u http://127.0.0.1:3000 -t 10

Then view:

http://127.0.0.1:8000

SQLite Database

VulnForge Ultimate uses SQLite for local persistence.

Typical database file:

vulnforge.db

Check it:

ls -lh vulnforge.db

Open it:

sqlite3 vulnforge.db

Inside SQLite:

.tables

Exit:

.quit

SQLite does not require a separate database server.

Scan → Database → Dashboard

             Target
                │
                ▼
        VulnForge Ultimate
                │
                ▼
       Detection Templates
                │
                ▼
        Findings / Evidence
                │
                ▼
          vulnforge.db
                │
                ▼
        Live Dashboard :8000

The database and dashboard are local components. A scan should be run from the same project environment that contains the intended VulnForge Ultimate installation.

Reports

Depending on the installed release and enabled modules, VulnForge Ultimate can provide scan/finding output for further analysis and reporting.

Before submitting any security report to a third party:

Review the raw evidence.

Reproduce the behavior manually.

Confirm the security impact.

Remove unnecessary sensitive data.

Follow the target's vulnerability disclosure policy.

Project Structure

A typical v1 installation contains components similar to:

VulnForge_Ultimate/
├── ai/
├── config/
├── core/
├── correlation/
├── engine/
├── extractor/
├── matcher/
├── output/
├── report/
├── reports/
├── risk/
├── templates/
├── terminal/
├── tools/
├── utils/
├── main.py
├── setup.py
├── requirements.txt
├── README.md
└── run.sh                 # if included by the release

The exact structure can change between releases.

Troubleshooting

run.sh: command not found

Use:

./run.sh

instead of:

run.sh

No such file or directory: .venv/bin/activate

You are probably in the wrong directory or the environment has not been created.

pwd
ls -la
python3 -m venv .venv
source .venv/bin/activate

VulnForge: command not found

source .venv/bin/activate
pip install -e .
which VulnForge
VulnForge --help

run.sh does not exist

Find available launchers:

find . -maxdepth 3 -type f \( -name "run.sh" -o -name "server.py" \) -print

Follow the launcher included in your exact release.

Port 8000 is already in use

ss -lntp | grep ':8000'

Stop the conflicting process if appropriate, or use the port configuration supported by your release.

Database is not being updated

Check:

ls -lh vulnforge.db

Then inspect the application output for database/persistence errors.

Responsible Use

VulnForge Ultimate performs active security testing.

Use it only against:

Systems you own

Local development applications

Deliberately vulnerable labs

CTF environments

Bug-bounty targets where the relevant testing is permitted

Systems for which you have explicit authorization

Do not scan random public infrastructure without permission.

License

See LICENSE.
