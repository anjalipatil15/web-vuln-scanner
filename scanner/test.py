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
def home():
    return """
    <html><body>
      <h1>Test App</h1>
      <a href="/search?q=hello">Search</a><br>
      <a href="/product?id=1">Product</a><br>
      <a href="/login">Login</a>
      <form action="/search" method="get">
        <input type="text" name="q" />
        <button type="submit">Search</button>
      </form>
    </body></html>
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