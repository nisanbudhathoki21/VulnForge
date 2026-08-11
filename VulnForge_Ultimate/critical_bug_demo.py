#!/usr/bin/env python3
# VulnForge – Critical Bug Testing (Single‑File, In‑Memory DB)
# Run: python vulnforge.py
# Visit: http://localhost:5005

from flask import Flask, request, render_template_string, session, redirect
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'vulnforge_secret'   # weak, for demo only

# ------------------ Create in‑memory database and sample data ------------------
def init_db():
    conn = sqlite3.connect(':memory:')   # in‑memory DB
    c = conn.cursor()
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL,
            description TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total REAL,
            status TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            user_id INTEGER,
            comment TEXT
        )
    ''')
    # Sample data (plaintext passwords)
    c.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'admin123', 1)")
    c.execute("INSERT INTO users (username, password, is_admin) VALUES ('alice', 'password', 0)")
    c.execute("INSERT INTO products (name, price, description) VALUES ('Laptop', 999.99, 'High‑performance laptop')")
    c.execute("INSERT INTO products (name, price, description) VALUES ('Mouse', 19.99, 'Wireless mouse')")
    c.execute("INSERT INTO orders (user_id, product_id, quantity, total, status) VALUES (2, 1, 1, 999.99, 'shipped')")
    conn.commit()
    return conn

# Global connection (in‑memory stays alive while app runs)
db_conn = init_db()

def get_db():
    """Return the in‑memory connection (no need to close)."""
    return db_conn

# ------------------ HTML templates (branded) ------------------
BASE_HTML = '''
<!doctype html>
<html>
<head>
    <title>VulnForge – Critical Bug Testing</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #f4f4f4; }
        h1 { color: #d9534f; }
        .container { max-width: 900px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .vuln-badge { background: #d9534f; color: white; padding: 3px 10px; border-radius: 5px; font-size: 0.8em; }
        nav a { margin-right: 15px; }
        .flash { background: #f0ad4e; padding: 10px; border-radius: 5px; }
        .admin-box { background: #f2dede; padding: 10px; border: 1px solid #ebccd1; }
        .vuln-tip { background: #d9edf7; padding: 8px; border-left: 4px solid #31708f; margin: 10px 0; }
    </style>
</head>
<body>
<div class="container">
    <h1>⚡ VulnForge <span class="vuln-badge">Critical Bug Testing</span></h1>
    <nav>
        <a href="/">Home</a>
        <a href="/admin">Admin Panel</a>
        <a href="/logout">Logout</a>
    </nav>
    <hr>
    {% block content %}{% endblock %}
</div>
</body>
</html>
'''

LOGIN_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div>
    <h2>Login</h2>
    <form method="POST">
        Username: <input name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</div>
''')

INDEX_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div>
    <h2>Welcome, {{ user }}!</h2>
    <div class="vuln-tip">
        <strong>🔥 Critical Vulnerabilities to Test:</strong>
        <ul>
            <li><strong>SQL Injection</strong> – login with <code>' OR 1=1 --</code></li>
            <li><strong>Stored XSS</strong> – post a review with <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
            <li><strong>Reflected XSS</strong> – use the search box below</li>
            <li><strong>IDOR</strong> – change order ID in URL: <code>/order/1</code> → <code>/order/2</code></li>
            <li><strong>No Auth</strong> – access <code>/admin</code> without logging in</li>
            <li><strong>Plaintext Passwords</strong> – see them in the admin panel</li>
        </ul>
    </div>
    <h3>Products</h3>
    <form method="GET" action="/search">
        Search (SQLi + XSS): <input name="q"> <input type="submit" value="Search">
    </form>
    <ul>
    {% for p in products %}
        <li>{{ p[1] }} – ${{ p[2] }} <a href="/product/{{ p[0] }}">View</a></li>
    {% endfor %}
    </ul>
</div>
''')

PRODUCT_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div>
    <h2>{{ product[1] }}</h2>
    <p>Price: ${{ product[2] }}</p>
    <p>{{ product[3] }}</p>
    <h3>Reviews (Stored XSS vulnerable)</h3>
    <ul>
    {% for r in reviews %}
        <li>{{ r[2]|safe }}</li>   <!-- INTENTIONALLY UNSAFE -->
    {% endfor %}
    </ul>
    <form method="POST">
        <textarea name="comment" placeholder="Write a review..."></textarea>
        <input type="submit" value="Post Review">
    </form>
    <a href="/">← Back</a>
</div>
''')

ADMIN_HTML = BASE_HTML.replace('{% block content %}{% endblock %}', '''
<div class="admin-box">
    <h2>👑 Admin Panel (No authentication required!)</h2>
    <h3>All Orders</h3>
    <ul>
    {% for o in orders %}
        <li>Order #{{ o[0] }} – User {{ o[1] }} – Total ${{ o[4] }} – Status {{ o[5] }}</li>
    {% endfor %}
    </ul>
    <h3>All Users (plaintext passwords exposed)</h3>
    <ul>
    {% for u in users %}
        <li>{{ u[1] }} ({{ 'admin' if u[3] else 'user' }}) – password: <code>{{ u[2] }}</code></li>
    {% endfor %}
    </ul>
</div>
''')

# ------------------ Routes ------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # VULNERABLE: SQL injection
        conn = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cur = conn.execute(query)
        user = cur.fetchone()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            return redirect('/')
        else:
            error = 'Invalid credentials'
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    conn = get_db()
    products = conn.execute('SELECT * FROM products').fetchall()
    return render_template_string(INDEX_HTML, user=session['username'], products=products)

@app.route('/search')
def search():
    q = request.args.get('q', '')
    # VULNERABLE: SQL injection & reflected XSS
    conn = get_db()
    products = conn.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'").fetchall()
    # Reflected XSS – no escaping
    html = f'''
    <h2>Search results for: {q}</h2>
    <ul>
    '''
    for p in products:
        html += f'<li>{p[1]} – ${p[2]}</li>'
    html += '</ul><a href="/">← Back</a>'
    return html

@app.route('/product/<int:pid>', methods=['GET', 'POST'])
def product(pid):
    if 'user_id' not in session:
        return redirect('/login')
    conn = get_db()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (pid,)).fetchone()
    reviews = conn.execute('SELECT * FROM reviews WHERE product_id = ?', (pid,)).fetchall()
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        # VULNERABLE: stored XSS
        conn.execute('INSERT INTO reviews (product_id, user_id, comment) VALUES (?, ?, ?)',
                     (pid, session['user_id'], comment))
        conn.commit()
        return redirect(f'/product/{pid}')
    return render_template_string(PRODUCT_HTML, product=product, reviews=reviews)

@app.route('/order/<int:oid>')
def order(oid):
    # VULNERABLE: IDOR – no ownership check
    if 'user_id' not in session:
        return redirect('/login')
    conn = get_db()
    order = conn.execute('SELECT * FROM orders WHERE id = ?', (oid,)).fetchone()
    if not order:
        return 'Order not found', 404
    return f'''
    <h2>Order #{order['id']}</h2>
    <p>User ID: {order['user_id']}</p>
    <p>Product ID: {order['product_id']}</p>
    <p>Quantity: {order['quantity']}</p>
    <p>Total: ${order['total']}</p>
    <p>Status: {order['status']}</p>
    <a href="/">← Back</a>
    '''

@app.route('/admin')
def admin():
    # VULNERABLE: no authentication
    conn = get_db()
    orders = conn.execute('SELECT * FROM orders').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    return render_template_string(ADMIN_HTML, orders=orders, users=users)

# ------------------ Main ------------------
if __name__ == '__main__':
    print("🔥 VulnForge – Critical Bug Testing")
    print("👉 Running on http://localhost:6000")
    print("⚠️  This app is INTENTIONALLY INSECURE. Use only for ethical testing.")
    app.run(host='127.0.0.1', port=5005, debug=True)
