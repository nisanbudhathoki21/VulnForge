from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import html
import sys

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/" and qs:
            # Intentionally vulnerable: reflects the raw query value
            # unescaped, for any of the common param names.
            raw_value = ""
            for key in ("q", "query", "search", "keyword", "s", "term", "text", "message", "comment", "name"):
                if key in qs:
                    raw_value = qs[key][0]
                    break
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body>Results for: {raw_value}</body></html>".encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b"<html><body>home page, nothing special here. status ok.</body></html>")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()

