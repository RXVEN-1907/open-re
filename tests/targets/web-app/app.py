#!/usr/bin/env python3
"""
Test Web Application with Known Vulnerabilities
This is a deliberately vulnerable FastAPI application for testing security scanners.
DO NOT DEPLOY TO PRODUCTION - For testing purposes only!
"""

from fastapi import FastAPI, Request, Form, Query, Header, Cookie, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
import os
import re
import sqlite3
import hashlib
import secrets
import base64
from datetime import datetime, timedelta

app = FastAPI(
    title="Open-RE Test Target",
    description="Deliberately vulnerable web app for security scanner testing",
    version="1.0.0"
)

# CORS misconfiguration - allows all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store (insecure)
sessions = {}
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "user": {"password": "password123", "role": "user"},
    "test": {"password": "test", "role": "user"},
}

# SQLite database for SQL injection demo
DB_PATH = "/tmp/test.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT,
        role TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        price REAL,
        description TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        product_id INTEGER,
        author TEXT,
        content TEXT,
        created_at TEXT
    )""")
    # Insert test data
    c.execute("INSERT OR IGNORE INTO users (username, password, email, role) VALUES ('admin', 'admin123', 'admin@example.com', 'admin')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, role) VALUES ('user', 'password123', 'user@example.com', 'user')")
    c.execute("INSERT OR IGNORE INTO products (name, price, description) VALUES ('Product A', 29.99, 'A great product')")
    c.execute("INSERT OR IGNORE INTO products (name, price, description) VALUES ('Product B', 49.99, 'Another product')")
    c.execute("INSERT OR IGNORE INTO comments (product_id, author, content, created_at) VALUES (1, 'user1', 'Great product!', '2024-01-01')")
    conn.commit()
    conn.close()

init_db()

# =============================================================================
# VULNERABILITY 1: SQL Injection in /search endpoint
# =============================================================================
@app.get("/search")
async def search(q: str = Query("", description="Search query")):
    """VULNERABLE: Direct string concatenation in SQL query"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULNERABLE: No parameterization
    query = f"SELECT name, price, description FROM products WHERE name LIKE '%{q}%'"
    try:
        c.execute(query)
        results = c.fetchall()
    except Exception as e:
        results = []
    conn.close()
    return {"query": q, "results": [{"name": r[0], "price": r[1], "description": r[2]} for r in results]}


# =============================================================================
# VULNERABILITY 2: SQL Injection in /login endpoint
# =============================================================================
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """VULNERABLE: SQL injection in login"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULNERABLE: String concatenation
    query = f"SELECT username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        c.execute(query)
        user = c.fetchone()
    except Exception as e:
        user = None
    conn.close()

    if user:
        session_id = secrets.token_urlsafe(32)
        sessions[session_id] = {"username": user[0], "role": user[2]}
        response = JSONResponse({"success": True, "session_id": session_id})
        response.set_cookie("session_id", session_id, httponly=False, secure=False, samesite="lax")
        return response
    raise HTTPException(status_code=401, detail="Invalid credentials")


# =============================================================================
# VULNERABILITY 3: XSS in /comment endpoint (stored XSS)
# =============================================================================
@app.post("/comment")
async def add_comment(product_id: int = Form(...), author: str = Form(...), content: str = Form(...)):
    """VULNERABLE: Stored XSS - no output encoding"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Using parameterized query here (not vulnerable to SQLi)
    c.execute("INSERT INTO comments (product_id, author, content, created_at) VALUES (?, ?, ?, ?)",
              (product_id, author, content, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Comment added"}


@app.get("/comments/{product_id}")
async def get_comments(product_id: int):
    """VULNERABLE: Returns raw user content without escaping"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT author, content, created_at FROM comments WHERE product_id = ?", (product_id,))
    comments = c.fetchall()
    conn.close()
    # Returns raw HTML - XSS vulnerability
    return HTMLResponse(content="<br>".join([f"<b>{c[0]}</b>: {c[1]}" for c in comments]))


# =============================================================================
# VULNERABILITY 4: Path Traversal in /file endpoint
# =============================================================================
@app.get("/file")
async def read_file(path: str = Query(..., description="File path to read")):
    """VULNERABLE: Path traversal - no validation"""
    try:
        # VULNERABLE: No path validation
        with open(path, "r") as f:
            content = f.read()
        return PlainTextResponse(content=content)
    except Exception as e:
        raise HTTPException(status_code=404, detail="File not found")


# =============================================================================
# VULNERABILITY 5: Information Disclosure in /debug endpoint
# =============================================================================
@app.get("/debug")
async def debug_info(request: Request):
    """VULNERABLE: Exposes sensitive debug information"""
    return {
        "environment": dict(os.environ),
        "headers": dict(request.headers),
        "cookies": dict(request.cookies),
        "server_info": {
            "python_version": "3.11",
            "framework": "FastAPI",
            "database_path": DB_PATH,
        },
        "sessions": sessions,  # Exposes all sessions!
    }


# =============================================================================
# VULNERABILITY 6: Missing Security Headers
# =============================================================================
@app.get("/no-headers")
async def no_security_headers():
    """Endpoint with no security headers - will trigger header findings"""
    return {"message": "This endpoint has no security headers"}


# =============================================================================
# VULNERABILITY 7: Insecure Cookie Configuration
# =============================================================================
@app.get("/set-cookie")
async def set_insecure_cookie(response: Response):
    """VULNERABLE: Sets cookies without Secure, HttpOnly, SameSite"""
    response.set_cookie("insecure_cookie", "test_value", httponly=False, secure=False, samesite="none")
    response.set_cookie("session_token", secrets.token_urlsafe(32), httponly=False, secure=False)
    return {"message": "Insecure cookies set"}


# =============================================================================
# VULNERABILITY 8: Directory Listing Simulation
# =============================================================================
@app.get("/files")
async def list_files(path: str = Query(".", description="Directory path")):
    """VULNERABLE: Simulates directory listing"""
    try:
        # VULNERABLE: Allows directory traversal
        abs_path = os.path.abspath(path)
        files = os.listdir(abs_path)
        file_list = []
        for f in files:
            fpath = os.path.join(abs_path, f)
            stat = os.stat(fpath)
            file_list.append({
                "name": f,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "is_dir": os.path.isdir(fpath)
            })
        return {"path": path, "files": file_list}
    except Exception as e:
        raise HTTPException(status_code=404, detail="Directory not found")


# =============================================================================
# VULNERABILITY 9: Weak Authentication (No Rate Limiting)
# =============================================================================
@app.post("/api/login")
async def api_login(request: Request):
    """VULNERABLE: No rate limiting on authentication endpoint"""
    data = await request.json()
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, role FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        return {"success": True, "token": secrets.token_urlsafe(32), "role": user[1]}
    return {"success": False, "error": "Invalid credentials"}


# =============================================================================
# VULNERABILITY 10: Server-Side Template Injection (SSTI) - Jinja2
# =============================================================================
@app.get("/template")
async def render_template(template: str = Query("Hello {{ name }}!", description="Template string")):
    """VULNERABLE: SSTI - renders user-controlled template"""
    from jinja2 import Template
    try:
        t = Template(template)
        # VULNERABLE: User controls template
        return HTMLResponse(content=t.render(name="user", config=os.environ))
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# VULNERABILITY 11: Information Disclosure via Error Messages
# =============================================================================
@app.get("/error")
async def trigger_error(type: str = Query("value", description="Error type")):
    """VULNERABLE: Detailed error messages"""
    if type == "value":
        raise ValueError("This is a detailed error message with stack trace")
    elif type == "key":
        raise KeyError("Missing key: secret_api_key_12345")
    elif type == "sql":
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM non_existent_table")  # This will fail
        conn.close()
    return {"error": "Triggered"}


# =============================================================================
# VULNERABILITY 12: XXE Simulation (via XML parsing)
# =============================================================================
@app.post("/xml")
async def parse_xml(request: Request):
    """VULNERABLE: XXE - parses user XML without disabling external entities"""
    import xml.etree.ElementTree as ET
    body = await request.body()
    try:
        # VULNERABLE: No XXE protection
        root = ET.fromstring(body)
        return {"parsed": ET.tostring(root).decode()}
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# VULNERABILITY 13: Open Redirect
# =============================================================================
@app.get("/redirect")
async def open_redirect(url: str = Query(..., description="URL to redirect to")):
    """VULNERABLE: Open redirect - no validation"""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=url)


# =============================================================================
# VULNERABILITY 14: CORS Misconfiguration (already configured globally)
# =============================================================================
@app.get("/cors-test")
async def cors_test():
    """Endpoint to test CORS misconfiguration"""
    return {"message": "CORS test endpoint", "vulnerable": True}


# =============================================================================
# VULNERABILITY 15: Weak Password Policy
# =============================================================================
@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), email: str = Form(...)):
    """VULNERABLE: No password strength validation"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                  (username, password, email, "user"))
        conn.commit()
        return {"success": True, "message": "User registered"}
    except sqlite3.IntegrityError:
        return {"success": False, "error": "User already exists"}
    finally:
        conn.close()


# =============================================================================
# Health check endpoint (safe)
# =============================================================================
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "openre-test-target"}


# =============================================================================
# Technology disclosure endpoints
# =============================================================================
@app.get("/api/version")
async def version():
    return {"version": "1.0.0", "framework": "FastAPI", "python": "3.11"}

@app.get("/server-info")
async def server_info():
    return {"server": "uvicorn", "version": "0.27.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)