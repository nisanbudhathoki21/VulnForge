from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <html>
    <head><title>VulnForge Demo Lab</title></head>
    <body>
        <h1>VulnForge Vulnerable Demo Lab</h1>

        <h2>Reflected XSS</h2>
        <form action="/search">
            <input name="q" placeholder="Search">
            <button>Search</button>
        </form>

        <h2>Open Redirect</h2>
        <form action="/redirect">
            <input name="url" placeholder="URL">
            <button>Redirect</button>
        </form>

        <h2>Path Traversal</h2>
        <form action="/file">
            <input name="name" value="test.txt">
            <button>Read File</button>
        </form>

        <h2>IDOR/BOLA Demo</h2>
        <p>Try /user/100 and /user/101</p>
    </body>
    </html>
    """

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<html><body><h1>Search results</h1><p>You searched for: {q}</p></body></html>"

@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    return redirect(url)

@app.route("/file")
def file_read():
    name = request.args.get("name", "test.txt")

    try:
        with open(name, "r") as f:
            content = f.read()
    except Exception as e:
        content = str(e)

    return f"<pre>{content}</pre>"

USERS = {
    "100": {"name": "Alice", "email": "alice@example.local"},
    "101": {"name": "Bob", "email": "bob@example.local"},
}

@app.route("/user/<user_id>")
def user(user_id):
    account = USERS.get(user_id)

    if not account:
        return "User not found", 404

    return {
        "id": user_id,
        "name": account["name"],
        "email": account["email"],
    }

@app.route("/ssti")
def ssti():
    name = request.args.get("name", "Guest")

    # Intentionally vulnerable SSTI demonstration.
    template = f"""
    <html>
    <body>
        <h1>Hello {name}</h1>
    </body>
    </html>
    """

    return render_template_string(template)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
