#!/usr/bin/env python3
"""
Simple vulnerable test server for openre-scan testing.
Serves intentionally vulnerable pages for security scanner testing.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import json
import os

class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        
        # Add vulnerable headers
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Server', 'TestServer/1.0 (Ubuntu)')
        self.send_header('X-Powered-By', 'PHP/7.4.3')
        self.send_header('X-Debug-Token', 'abc123')
        # Missing security headers intentionally
        self.end_headers()
        
        if path == '/':
            self.wfile.write(b'''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test App</title>
    <meta name="generator" content="WordPress 5.8">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.0/dist/css/bootstrap.min.css">
    <script>var apiKey = "sk_test_123456789";</script>
</head>
<body>
    <h1>Welcome to Vulnerable Test App</h1>
    <form action="/login" method="GET">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login (GET)</button>
    </form>
    <form action="/search" method="POST">
        <input type="text" name="q" placeholder="Search">
        <button type="submit">Search</button>
    </form>
    <a href="http://insecure.example.com/resource">Insecure Link</a>
    <a href="mailto:admin@example.com">Contact</a>
    <script>eval('alert("xss")')</script>
</body>
</html>
''')
        elif path == '/login':
            username = query.get('username', [''])[0]
            password = query.get('password', [''])[0]
            self.wfile.write(f'''
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h1>Login Result</h1>
    <p>Username: {username}</p>
    <p>Password: {password}</p>
    <p>Notice: Password sent via GET!</p>
    <a href="/">Back</a>
</body>
</html>
'''.encode())
        elif path == '/robots.txt':
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'''
User-agent: *
Disallow: /admin/
Disallow: /secret/
Disallow: /backup/
Disallow: /.git/
Allow: /
''')
        elif path == '/sitemap.xml':
            self.send_header('Content-Type', 'application/xml')
            self.end_headers()
            self.wfile.write(b'''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>https://example.com/</loc></url>
    <url><loc>https://example.com/login</loc></url>
    <url><loc>https://example.com/admin</loc></url>
    <url><loc>https://example.com/secret</loc></url>
</urlset>''')
        elif path == '/admin':
            self.wfile.write(b'''
<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
    <h1>Admin Panel</h1>
    <p>Welcome admin!</p>
    <a href="/">Back</a>
</body>
</html>
''')
        elif path == '/secret':
            self.wfile.write(b'Secret data: API_KEY=sk_live_abcdef123456')
        elif path.startswith('/.git/'):
            self.wfile.write(b'Git repository data')
        elif path == '/.env':
            self.wfile.write(b'DATABASE_PASSWORD=secret123\nAPI_KEY=sk_live_xyz789')
        elif path == '/config.php':
            self.wfile.write(b'<?php $db_pass = "dbpassword123"; ?>')
        else:
            self.wfile.write(b'''
<!DOCTYPE html>
<html>
<head><title>404</title></head>
<body><h1>404 Not Found</h1></body>
</html>
''')
    
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else ""
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Server', 'TestServer/1.0 (Ubuntu)')
        self.send_header('X-Powered-By', 'PHP/7.4.3')
        self.end_headers()
        
        if path == '/search':
            q = urllib.parse.parse_qs(body).get('q', [''])[0]
            self.wfile.write(f'''
<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <h1>Search Results for: {q}</h1>
    <p>No results found.</p>
    <a href="/">Back</a>
</body>
</html>
'''.encode())
        else:
            self.wfile.write(b'<h1>POST received</h1>')
    
    def do_HEAD(self):
        # For sensitive file checks
        path = urllib.parse.urlparse(self.path).path
        sensitive_paths = ['/.git/', '/.env', '/config.php', '/wp-config.php', 
                          '/settings.py', '/docker-compose.yml', '/Dockerfile',
                          '/README.md', '/package.json', '/composer.json',
                          '/requirements.txt', '/pom.xml', '/build.gradle',
                          '/.htaccess', '/web.config', '/crossdomain.xml',
                          '/clientaccesspolicy.xml']
        
        if path in sensitive_paths or path.startswith('/.git/'):
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress default log messages
        pass

if __name__ == '__main__':
    server = HTTPServer(('localhost', 8080), VulnerableHandler)
    print("Starting vulnerable test server on http://localhost:8080")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()
