"""
Deliberately vulnerable Flask app for testing the scanner locally.
DO NOT deploy this anywhere reachable from the internet.

Run:  pip install flask
      python3 vuln_test_app.py
Then point your scanner at http://127.0.0.1:5000/

Routes:
  GET  /search?q=...          -> reflected XSS (unescaped output)
  GET  /product?id=...        -> SQL injection (string-formatted query)
  GET  /login  (form)         -> renders a POST login form
  POST /login  (username,pw)  -> SQL injection via string-formatted query
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)

DB = "test.db"


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'sup3rsecret')")
    conn.commit()
    conn.close()


@app.route("/")
@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>TechMart</title>

        <style>

            *{
                margin:0;
                padding:0;
                box-sizing:border-box;
                font-family:Segoe UI, Arial, sans-serif;
            }

            body{
                background:#f8fafc;
                color:#1e293b;
            }

            .navbar{
                background:#0f172a;
                color:white;
                padding:18px 40px;
                display:flex;
                justify-content:space-between;
                align-items:center;
            }

            .logo{
                font-size:1.5rem;
                font-weight:bold;
            }

            .hero{
                text-align:center;
                padding:80px 20px;
                background:linear-gradient(
                    135deg,
                    #2563eb,
                    #0ea5e9
                );
                color:white;
            }

            .hero h1{
                font-size:3rem;
                margin-bottom:15px;
            }

            .hero p{
                font-size:1.1rem;
                opacity:.9;
            }

            .products{
                max-width:1200px;
                margin:auto;
                padding:50px 20px;
            }

            .products h2{
                margin-bottom:30px;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(auto-fit,minmax(250px,1fr));
                gap:25px;
            }

            .card{
                background:white;
                border-radius:14px;
                overflow:hidden;
                box-shadow:0 5px 20px rgba(0,0,0,.08);
            }

            .image{
                height:180px;
                background:#cbd5e1;
            }

            .content{
                padding:20px;
            }

            .content h3{
                margin-bottom:10px;
            }

            .price{
                color:#2563eb;
                font-size:1.2rem;
                font-weight:bold;
                margin:10px 0;
            }

            .btn{
                display:inline-block;
                text-decoration:none;
                background:#2563eb;
                color:white;
                padding:10px 14px;
                border-radius:8px;
            }

            .search-section{
                max-width:1200px;
                margin:auto;
                padding:20px;
            }

            .search-box{
                background:white;
                padding:25px;
                border-radius:14px;
                box-shadow:0 5px 20px rgba(0,0,0,.08);
            }

            .search-box h2{
                margin-bottom:15px;
            }

            form{
                display:flex;
                gap:10px;
            }

            input{
                flex:1;
                padding:12px;
                border:1px solid #cbd5e1;
                border-radius:8px;
            }

            button{
                padding:12px 20px;
                border:none;
                border-radius:8px;
                background:#2563eb;
                color:white;
                cursor:pointer;
            }

            footer{
                margin-top:60px;
                text-align:center;
                padding:30px;
                background:#0f172a;
                color:white;
            }

        </style>

    </head>

    <body>

        <nav class="navbar">
            <div class="logo">TechMart</div>
            <div>Products | Login | Cart</div>
        </nav>

        <section class="hero">
            <h1>Latest Tech Deals</h1>
            <p>Discover laptops, phones, accessories and more.</p>
        </section>

        <section class="search-section">

            <div class="search-box">

                <h2>Search Products</h2>

                <form action="/search" method="get">
                    <input
                        type="text"
                        name="q"
                        placeholder="Search products..."
                    >
                    <button type="submit">
                        Search
                    </button>
                </form>

            </div>

        </section>

        <section class="products">

            <h2>Featured Products</h2>

            <div class="grid">

                <div class="card">
                    <div class="image"></div>
                    <div class="content">
                        <h3>Gaming Laptop</h3>
                        <div class="price">$999</div>
                        <a href="/product?id=1" class="btn">
                            View Product
                        </a>
                    </div>
                </div>

                <div class="card">
                    <div class="image"></div>
                    <div class="content">
                        <h3>Wireless Headphones</h3>
                        <div class="price">$149</div>
                        <a href="/product?id=2" class="btn">
                            View Product
                        </a>
                    </div>
                </div>

                <div class="card">
                    <div class="image"></div>
                    <div class="content">
                        <h3>Smartphone Pro</h3>
                        <div class="price">$799</div>
                        <a href="/product?id=3" class="btn">
                            View Product
                        </a>
                    </div>
                </div>

            </div>

        </section>

        <footer>
            © 2026 TechMart. All rights reserved.
        </footer>

    </body>
    </html>
    """
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Test Application</title>

        <style>

            *{
                margin:0;
                padding:0;
                box-sizing:border-box;
                font-family:Segoe UI, Arial, sans-serif;
            }

            body{
                background:#0f172a;
                color:#e2e8f0;
                min-height:100vh;
                display:flex;
                justify-content:center;
                align-items:center;
                padding:40px;
            }

            .container{
                width:100%;
                max-width:800px;
                background:#1e293b;
                border-radius:16px;
                padding:40px;
                box-shadow:0 0 30px rgba(0,0,0,.35);
            }

            h1{
                margin-bottom:10px;
                font-size:2rem;
            }

            .subtitle{
                color:#94a3b8;
                margin-bottom:30px;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
                gap:20px;
                margin-bottom:30px;
            }

            .card{
                background:#334155;
                border-radius:12px;
                padding:20px;
            }

            .card h3{
                margin-bottom:10px;
                color:#f8fafc;
            }

            .card p{
                color:#cbd5e1;
                font-size:.95rem;
                margin-bottom:15px;
            }

            .btn{
                display:inline-block;
                text-decoration:none;
                background:#2563eb;
                color:white;
                padding:10px 14px;
                border-radius:8px;
                transition:.2s;
            }

            .btn:hover{
                background:#1d4ed8;
            }

            .search-box{
                background:#334155;
                padding:20px;
                border-radius:12px;
            }

            .search-box h3{
                margin-bottom:15px;
            }

            form{
                display:flex;
                gap:10px;
            }

            input{
                flex:1;
                padding:12px;
                border:none;
                border-radius:8px;
                background:#0f172a;
                color:white;
            }

            button{
                background:#22c55e;
                color:white;
                border:none;
                padding:12px 20px;
                border-radius:8px;
                cursor:pointer;
            }

            button:hover{
                background:#16a34a;
            }

            .warning{
                margin-top:25px;
                background:#7f1d1d;
                color:#fecaca;
                padding:15px;
                border-radius:10px;
                font-size:.9rem;
            }

        </style>
    </head>

    <body>

        <div class="container">

            <h1>Vulnerable Test Application</h1>

            <p class="subtitle">
                Intentionally insecure application for security scanner testing.
            </p>

            <div class="grid">

                <div class="card">
                    <h3>Reflected XSS</h3>
                    <p>
                        Search endpoint reflects user input without output encoding.
                    </p>
                    <a href="/search?q=hello" class="btn">
                        Test XSS
                    </a>
                </div>

                <div class="card">
                    <h3>SQL Injection</h3>
                    <p>
                        Product endpoint builds SQL queries using raw user input.
                    </p>
                    <a href="/product?id=1" class="btn">
                        Test SQLi
                    </a>
                </div>

                <div class="card">
                    <h3>Login Form</h3>
                    <p>
                        Vulnerable authentication form using unsafe SQL queries.
                    </p>
                    <a href="/login" class="btn">
                        Open Login
                    </a>
                </div>

            </div>

            <div class="search-box">

                <h3>Quick Search</h3>

                <form action="/search" method="get">

                    <input
                        type="text"
                        name="q"
                        placeholder="Enter search term..."
                    >

                    <button type="submit">
                        Search
                    </button>

                </form>

            </div>

            <div class="warning">
                WARNING: This application is intentionally vulnerable and should only be used in a local testing environment.
            </div>

        </div>

    </body>
    </html>
    """


# --- Reflected XSS (GET) ---
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: unescaped reflection
    return f"<html><body>You searched for: {q}</body></html>"


# --- SQL Injection (GET) ---
@app.route("/product")
def product():
    product_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB)
    try:
        # VULNERABLE: string-formatted query
        query = f"SELECT id FROM users WHERE id = {product_id}"
        cur = conn.execute(query)
        rows = cur.fetchall()
        return f"<html><body>Found {len(rows)} rows</body></html>"
    except sqlite3.Error as e:
        # Deliberately leaks the DB error, like a real vulnerable app
        return f"<html><body>Database error: {e}</body></html>", 500
    finally:
        conn.close()


# --- SQL Injection (POST form) ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <html><body>
          <form action="/login" method="post">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Login</button>
          </form>
        </body></html>
        """

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB)
    try:
        # VULNERABLE: string-formatted query
        query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
        cur = conn.execute(query)
        row = cur.fetchone()
        if row:
            return "<html><body>Welcome, logged in!</body></html>"
        return "<html><body>Invalid credentials</body></html>"
    except sqlite3.Error as e:
        return f"<html><body>Database error: {e}</body></html>", 500
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)