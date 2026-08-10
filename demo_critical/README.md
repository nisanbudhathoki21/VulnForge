# VulnForge Critical Bug Demo

This is a **local, intentionally vulnerable Flask website** made only for testing the VulnForge scanner.

It is designed to expose clear signals for critical/high-impact vulnerability templates:

| Endpoint | Intended finding |
|---|---|
| `/sqli?id=1` | SQL Injection |
| `/cmd?host=127.0.0.1` | OS Command Injection |
| `/ssti?name=VulnForge` | Server-Side Template Injection |
| `/admin?role=user` | Authorization / privilege bypass demo |
| `/file?name=notes.txt` | Path Traversal / arbitrary file read |
| `/ssrf?url=http://127.0.0.1:5001/` | Server-Side Request Forgery |

## Run

From the `VulnForge/demo_critical` directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

The demo listens only on:

`http://127.0.0.1:5001`

Do not expose this application to the Internet or bind it to `0.0.0.0`.

## Test with VulnForge

From the main VulnForge directory, use the scanner against:

```bash
VulnForge -u http://127.0.0.1:5001 --debug
```

or, depending on your current CLI:

```bash
python main.py -u http://127.0.0.1:5001 --debug
```

The purpose is to verify that VulnForge's YAML templates produce different findings from the deliberately vulnerable endpoints.

## Important

This application is intentionally insecure. It is a controlled lab target, not production code.
