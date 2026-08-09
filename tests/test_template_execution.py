#!/usr/bin/env python3

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


# ============================================================
# Make the VulnForge project root importable
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


from engine.scanner import Scanner


# ============================================================
# Local test HTTP server
# ============================================================

class TestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        # ----------------------------------------------------
        # Simulated authenticated "current user" endpoint
        # ----------------------------------------------------
        if self.path == "/api/me":
            body = (
                b'{"id":100,'
                b'"email":"test@example.com",'
                b'"username":"testuser"}'
            )

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.send_header(
                "Content-Length",
                str(len(body))
            )
            self.end_headers()

            self.wfile.write(body)
            return

        # ----------------------------------------------------
        # Simulated second user
        # ----------------------------------------------------
        if self.path == "/api/users/101":
            body = (
                b'{"id":101,'
                b'"email":"other@example.com",'
                b'"username":"otheruser"}'
            )

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.send_header(
                "Content-Length",
                str(len(body))
            )
            self.end_headers()

            self.wfile.write(body)
            return

        # ----------------------------------------------------
        # Default response
        # ----------------------------------------------------
        body = b'{"status":"ok"}'

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "application/json"
        )
        self.send_header(
            "Content-Length",
            str(len(body))
        )
        self.end_headers()

        self.wfile.write(body)

    def log_message(self, format, *args):
        """
        Disable HTTP server logging so the test output
        remains clean.
        """
        pass


# ============================================================
# Start local server
# ============================================================

def start_server():
    server = HTTPServer(
        ("127.0.0.1", 8765),
        TestHandler
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True
    )

    thread.start()

    return server


# ============================================================
# Main test
# ============================================================

def main():

    print("=" * 60)
    print("VULNFORGE TEMPLATE EXECUTION TEST")
    print("=" * 60)

    server = start_server()

    # Give the local HTTP server a moment to start.
    time.sleep(0.2)

    try:

        # ----------------------------------------------------
        # Create scanner
        # ----------------------------------------------------

        scanner = Scanner(
            url="http://127.0.0.1:8765",
            quiet=True,
            template_dir="templates/"
        )

        print("[INFO] Loading templates...")

        scanner.load_templates()

        print(
            f"[PASS] Templates loaded: "
            f"{len(scanner.templates)}"
        )

        if not scanner.templates:
            print("[FAIL] No templates loaded")
            return 1

        # ----------------------------------------------------
        # Runtime context
        # ----------------------------------------------------

        scanner.context.update({
            "own_id": 100,
            "own_email": "test@example.com",
            "own_username": "testuser",
            "own_uuid": "00000000-0000-0000-0000-000000000100"
        })

        print("[PASS] Scanner context initialized")

        # ----------------------------------------------------
        # Find BOLA numeric template
        # ----------------------------------------------------

        target_template = None

        for template in scanner.templates:

            if template.get("id") == "bola-numeric":
                target_template = template
                break

        if target_template is None:
            print(
                "[FAIL] bola-numeric template not found"
            )
            return 1

        print(
            "[PASS] Found template: "
            f"{target_template.get('id')}"
        )

        print(
            "[INFO] Template name: "
            f"{target_template.get('name', 'unknown')}"
        )

        print(
            "[INFO] Severity: "
            f"{target_template.get('severity', 'unknown')}"
        )

        print(
            "[INFO] Requests: "
            f"{len(target_template.get('requests', []))}"
        )

        # ----------------------------------------------------
        # Execute template
        # ----------------------------------------------------

        before = len(scanner.findings)

        print()
        print("[INFO] Executing template...")

        scanner._execute_template(
            target_template
        )

        after = len(scanner.findings)

        print()
        print(
            f"[INFO] Findings before execution: "
            f"{before}"
        )

        print(
            f"[INFO] Findings after execution: "
            f"{after}"
        )

        # ----------------------------------------------------
        # Display findings
        # ----------------------------------------------------

        if after > before:

            print()
            print("[PASS] Template execution produced a finding")

            new_findings = scanner.findings[before:after]

            for finding in new_findings:

                print()
                print("-" * 60)
                print(
                    f"Template : "
                    f"{finding.get('template_id')}"
                )
                print(
                    f"Name     : "
                    f"{finding.get('name')}"
                )
                print(
                    f"Severity : "
                    f"{finding.get('severity')}"
                )
                print(
                    f"Confirmed: "
                    f"{finding.get('confirmed')}"
                )

        else:

            print()
            print(
                "[PASS] Template executed without crashing"
            )

            print(
                "[INFO] No confirmed finding was produced."
            )

        # ----------------------------------------------------
        # Final result
        # ----------------------------------------------------

        print()
        print("=" * 60)
        print("TEMPLATE EXECUTION TEST COMPLETE")
        print("=" * 60)

        return 0

    except Exception as exc:

        print()
        print("=" * 60)
        print("TEMPLATE EXECUTION TEST FAILED")
        print("=" * 60)

        print()
        print(f"[FAIL] {type(exc).__name__}: {exc}")

        import traceback

        print()
        traceback.print_exc()

        return 1

    finally:

        server.shutdown()
        server.server_close()


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    raise SystemExit(main())
