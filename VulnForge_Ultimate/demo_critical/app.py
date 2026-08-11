from flask import Flask, request, render_template_string, jsonify
import sqlite3
import subprocess
import os

app = Flask(__name__)
DB = "demo.db"

def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    con.execute("DELETE FROM users")
    con.executemany("INSERT INTO users(username, role) VALUES (?, ?)",
                    [("alice", "user"), ("bob", "admin"), ("demo", "user")])
    con.commit()
    con.close()

@app.route("/")
def index():
    return """
    <h1>VulnForge Critical Bug Demo</h1>
    <p>Local-only intentionally vulnerable application for testing VulnForge templates.</p>
    <ul>
      <li><a href="/sqli?id=1">SQL Injection</a></li>
      <li><a href="/cmd?host=127.0.0.1">Command Injection</a></li>
      <li><a href="/ssti?name=VulnForge">SSTI</a></li>
      <li><a href="/admin?role=user">Authorization Bypass</a></li>
      <li><a href="/file?name=notes.txt">Path Traversal / File Read</a></li>
      <li><a href="/ssrf?url=http://127.0.0.1:5001/">SSRF</a></li>
    </ul>
    """

@app.route("/sqli")
def sqli():
    # INTENTIONALLY VULNERABLE: SQL is built directly from user input.
    user_id = request.args.get("id", "1")
    con = sqlite3.connect(DB)
    query = f"SELECT id, username, role FROM users WHERE id = {user_id}"
    rows = con.execute(query).fetchall()
    con.close()
    return jsonify({"query": query, "rows": rows})

@app.route("/cmd")
def cmd():
    # INTENTIONALLY VULNERABLE: user input reaches a shell command.
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True, stderr=subprocess.STDOUT)
    return "<pre>" + result + "</pre>"

@app.route("/ssti")
def ssti():
    # INTENTIONALLY VULNERABLE: user input becomes a Jinja template.
    name = request.args.get("name", "VulnForge")
    return render_template_string("Hello " + name)

@app.route("/admin")
def admin():
    # INTENTIONALLY VULNERABLE: authorization is controlled by a client parameter.
    role = request.args.get("role", "user")
    if role == "admin":
        return "<h2>Admin panel</h2><p>Critical demo: privileged content exposed.</p>"
    return "<h2>User page</h2><p>Not authorized.</p>"

@app.route("/file")
def file_read():
    # INTENTIONALLY VULNERABLE: path is not constrained to a safe directory.
    name = request.args.get("name", "notes.txt")
    with open(name, "r", encoding="utf-8") as f:
        return "<pre>" + f.read() + "</pre>"

@app.route("/ssrf")
def ssrf():
    # INTENTIONALLY VULNERABLE: arbitrary URL is fetched server-side.
    import urllib.request
    url = request.args.get("url", "http://127.0.0.1:5001/")
    with urllib.request.urlopen(url, timeout=3) as r:
        body = r.read(4096).decode("utf-8", errors="replace")
    return "<pre>" + body + "</pre>"

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=False)
